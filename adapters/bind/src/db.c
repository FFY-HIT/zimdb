/*
 * BOGI mmap-direct zone database for BIND dyndb.
 *
 * create_db: mmap .bogi only (no qpzone hydrate).
 * find / findnode / findrdataset: BOGI lookup to dns_rdataset.
 */

#include "db.h"

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include <isc/buffer.h>
#include <isc/lex.h>
#include <isc/mem.h>
#include <isc/refcount.h>
#include <isc/util.h>

#include <dns/db.h>
#include <dns/dbiterator.h>
#include <dns/fixedname.h>
#include <dns/message.h>
#include <dns/name.h>
#include <dns/rdata.h>
#include <dns/rdatastruct.h>
#include <dns/rdatalist.h>
#include <dns/rdataset.h>
#include <dns/rdatasetiter.h>
#include <dns/rdatatype.h>
#include <dns/result.h>
#include <dns/types.h>

#include "bogi23_export.h"
#include "instance.h"
#include "log.h"

#define BOGIDB_MAGIC	 ISC_MAGIC('B', 'G', 'D', 'B')
#define BOGINODE_MAGIC	 ISC_MAGIC('B', 'G', 'N', 'D')
#define VALID_BOGIDB(db) ((db) != NULL && (db)->common.impmagic == BOGIDB_MAGIC)
#define VALID_NODE(n)	 ((n) != NULL && (n)->magic == BOGINODE_MAGIC)

typedef struct bogidb bogidb_t;
typedef struct boginode boginode_t;

struct bogidb {
	dns_db_t common;
	bogi_instance_t *inst;
	Bogi23Reader reader;
	int reader_open;
	/* Single read-only version token. */
	int version_token;
};

struct boginode {
	unsigned int magic;
	isc_refcount_t references;
	bogidb_t *db;
	dns_fixedname_t fixed;
	dns_name_t *name;
	char owner[DNS_NAME_FORMATSIZE];
	bool exists;
	bool loaded;
	Bogi23OwnerGroup group;
	/* Per-type materialization for rdataset lifetime. */
	dns_rdatalist_t lists[ZIR3_NTYPES_MAX];
	dns_rdata_t *rdata_objs[ZIR3_NTYPES_MAX];
	unsigned char *wire_slab[ZIR3_NTYPES_MAX];
	size_t rdata_counts[ZIR3_NTYPES_MAX];
	bool list_ready[ZIR3_NTYPES_MAX];
};

static void
owner_from_name(const dns_name_t *name, char *buf, size_t buflen) {
	dns_name_format(name, buf, (unsigned int)buflen);
	/* dns_name_format omits root dot for absolute names ending at root;
	 * ensure trailing dot for BOGI absolute owners. */
	size_t n = strlen(buf);
	if (n + 1 < buflen && (n == 0 || buf[n - 1] != '.')) {
		buf[n] = '.';
		buf[n + 1] = '\0';
	}
}

static isc_result_t
rrtype_to_dns(const char *text, dns_rdatatype_t *typep) {
	isc_textregion_t reg;
	reg.base = (char *)text;
	reg.length = (unsigned int)strlen(text);
	return dns_rdatatype_fromtext(typep, &reg);
}

static isc_result_t
rrtype_to_text(dns_rdatatype_t type, char *buf, size_t buflen) {
	dns_rdatatype_format(type, buf, (unsigned int)buflen);
	return ISC_R_SUCCESS;
}

static void
node_clear_lists(boginode_t *node) {
	size_t i;
	bogidb_t *db = node->db;

	for (i = 0; i < ZIR3_NTYPES_MAX; i++) {
		if (node->rdata_objs[i] != NULL) {
			isc_mem_put(db->common.mctx, node->rdata_objs[i],
				    node->rdata_counts[i] *
					    sizeof(dns_rdata_t));
			node->rdata_objs[i] = NULL;
		}
		if (node->wire_slab[i] != NULL) {
			isc_mem_put(db->common.mctx, node->wire_slab[i],
				    node->rdata_counts[i] * 4096u);
			node->wire_slab[i] = NULL;
		}
		node->rdata_counts[i] = 0;
		node->list_ready[i] = false;
		dns_rdatalist_init(&node->lists[i]);
	}
	if (node->loaded) {
		bogi23_free_group(&db->reader, &node->group);
		node->loaded = false;
	}
}

static isc_result_t
node_load_group(boginode_t *node) {
	bogidb_t *db = node->db;
	int found = 0;

	if (node->loaded) {
		return ISC_R_SUCCESS;
	}
	if (bogi23_lookup_group(&db->reader, node->owner, &node->group,
				&found) != 0) {
		return ISC_R_FAILURE;
	}
	node->exists = (found != 0);
	node->loaded = (found != 0);
	if (!found) {
		(void)memset(&node->group, 0, sizeof(node->group));
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
materialize_type(boginode_t *node, dns_rdatatype_t type, size_t *slotp) {
	bogidb_t *db = node->db;
	size_t i;
	size_t slot = ZIR3_NTYPES_MAX;
	const Bogi23RRset *rrset = NULL;
	char want[16];
	isc_result_t result;
	isc_lex_t *lex = NULL;

	CHECK(rrtype_to_text(type, want, sizeof(want)));
	for (i = 0; i < strlen(want); i++) {
		if (want[i] >= 'a' && want[i] <= 'z') {
			want[i] = (char)(want[i] - 'a' + 'A');
		}
	}

	CHECK(node_load_group(node));
	if (!node->loaded) {
		return DNS_R_NXDOMAIN;
	}

	for (i = 0; i < node->group.count; i++) {
		if (node->group.sets[i].rrtype != NULL &&
		    strcmp(node->group.sets[i].rrtype, want) == 0) {
			rrset = &node->group.sets[i];
			slot = i;
			break;
		}
	}
	if (rrset == NULL) {
		return DNS_R_NXRRSET;
	}
	if (node->list_ready[slot]) {
		*slotp = slot;
		return ISC_R_SUCCESS;
	}

	node->rdata_counts[slot] = rrset->rdata_count;
	node->rdata_objs[slot] = isc_mem_get(
		db->common.mctx, rrset->rdata_count * sizeof(dns_rdata_t));
	(void)memset(node->rdata_objs[slot], 0,
		     rrset->rdata_count * sizeof(dns_rdata_t));
	node->wire_slab[slot] =
		isc_mem_get(db->common.mctx, rrset->rdata_count * 4096u);
	(void)memset(node->wire_slab[slot], 0, rrset->rdata_count * 4096u);

	dns_rdatalist_init(&node->lists[slot]);
	node->lists[slot].rdclass = dns_rdataclass_in;
	node->lists[slot].type = type;
	node->lists[slot].ttl = (dns_ttl_t)rrset->ttl;

	for (i = 0; i < rrset->rdata_count; i++) {
		isc_buffer_t source;
		isc_buffer_t target;
		unsigned char *wire = node->wire_slab[slot] + (i * 4096u);
		const char *text = rrset->rdatas[i];

		dns_rdata_init(&node->rdata_objs[slot][i]);
		isc_buffer_constinit(&source, text, strlen(text));
		isc_buffer_add(&source, strlen(text));
		isc_buffer_init(&target, wire, 4096u);
		isc_lex_create(db->common.mctx, 256, &lex);
		CHECK(isc_lex_openbuffer(lex, &source));
		CHECK(dns_rdata_fromtext(&node->rdata_objs[slot][i],
					 dns_rdataclass_in, type, lex,
					 dns_db_origin((dns_db_t *)db), 0,
					 db->common.mctx, &target, NULL));
		isc_lex_destroy(&lex);
		lex = NULL;
		ISC_LIST_APPEND(node->lists[slot].rdata,
				&node->rdata_objs[slot][i], link);
	}

	node->list_ready[slot] = true;
	*slotp = slot;
	result = ISC_R_SUCCESS;

cleanup:
	if (lex != NULL) {
		isc_lex_destroy(&lex);
	}
	return result;
}

static boginode_t *
node_create(bogidb_t *db, const dns_name_t *name) {
	boginode_t *node = isc_mem_get(db->common.mctx, sizeof(*node));
	*node = (boginode_t){ 0 };
	node->magic = BOGINODE_MAGIC;
	node->db = db;
	isc_refcount_init(&node->references, 1);
	node->name = dns_fixedname_initname(&node->fixed);
	dns_name_copy(name, node->name);
	owner_from_name(name, node->owner, sizeof(node->owner));
	return node;
}

static void
node_destroy(boginode_t *node) {
	bogidb_t *db = node->db;
	node_clear_lists(node);
	node->magic = 0;
	isc_mem_put(db->common.mctx, node, sizeof(*node));
}

/* --- dns_dbmethods --- */

static void
destroy(dns_db_t *db) {
	bogidb_t *bogi = (bogidb_t *)db;

	REQUIRE(VALID_BOGIDB(bogi));
	if (bogi->reader_open) {
		bogi23_trace_end(&bogi->reader);
		bogi23_close(&bogi->reader);
		bogi->reader_open = 0;
	}
	dns_name_free(&bogi->common.origin, bogi->common.mctx);
	isc_mem_putanddetach(&bogi->common.mctx, bogi, sizeof(*bogi));
}

static void
currentversion(dns_db_t *db, dns_dbversion_t **versionp) {
	bogidb_t *bogi = (bogidb_t *)db;
	REQUIRE(VALID_BOGIDB(bogi));
	REQUIRE(versionp != NULL && *versionp == NULL);
	*versionp = (dns_dbversion_t *)&bogi->version_token;
}

static isc_result_t
newversion(dns_db_t *db, dns_dbversion_t **versionp) {
	currentversion(db, versionp);
	return ISC_R_SUCCESS;
}

static void
attachversion(dns_db_t *db, dns_dbversion_t *source,
	      dns_dbversion_t **targetp) {
	UNUSED(db);
	REQUIRE(targetp != NULL && *targetp == NULL);
	*targetp = source;
}

static void
closeversion(dns_db_t *db, dns_dbversion_t **versionp,
	     bool commit DNS__DB_FLARG) {
	UNUSED(db);
	UNUSED(commit);
	REQUIRE(versionp != NULL && *versionp != NULL);
	*versionp = NULL;
}

static isc_result_t
findnode(dns_db_t *db, const dns_name_t *name, bool create,
	 dns_dbnode_t **nodep DNS__DB_FLARG) {
	bogidb_t *bogi = (bogidb_t *)db;
	boginode_t *node;
	int exists = 0;
	isc_result_t result;

	REQUIRE(VALID_BOGIDB(bogi));
	REQUIRE(nodep != NULL && *nodep == NULL);
	UNUSED(create);

	node = node_create(bogi, name);
	if (bogi23_node_exists(&bogi->reader, node->owner, &exists) != 0) {
		log_error("findnode: bogi23_node_exists failed for %s",
			  node->owner);
		node_destroy(node);
		return ISC_R_FAILURE;
	}
	node->exists = (exists != 0);
	/*
	 * Persistent zone DB: allow attaching a node for apex / existing names
	 * even when create=false (BIND zone load does this for NSEC3PARAM).
	 */
	if (!exists) {
		/* Also try lookup_group — ENT vs missing. */
		Bogi23OwnerGroup tmp;
		int found = 0;
		if (bogi23_lookup_group(&bogi->reader, node->owner, &tmp,
					&found) == 0 &&
		    found) {
			bogi23_free_group(&bogi->reader, &tmp);
			exists = 1;
			node->exists = true;
		} else if (found) {
			bogi23_free_group(&bogi->reader, &tmp);
		}
	}
	if (!exists && !create) {
		node_destroy(node);
		return ISC_R_NOTFOUND;
	}
	*nodep = (dns_dbnode_t *)node;
	result = ISC_R_SUCCESS;
	return result;
}

static void attachnode(dns_db_t *db, dns_dbnode_t *source,
		       dns_dbnode_t **targetp DNS__DB_FLARG);
static void detachnode(dns_db_t *db, dns_dbnode_t **targetp DNS__DB_FLARG);

/*
 * Rdataset holds a node ref (sdlz/builtin pattern) so data survives
 * qctx_clean()'s detachnode before message render.
 */
static void
bogi_rdataset_disassociate(dns_rdataset_t *rdataset DNS__DB_FLARG) {
	dns_dbnode_t *node = rdataset->rdlist.node;
	boginode_t *bnode = (boginode_t *)node;
	dns_db_t *db = (dns_db_t *)bnode->db;

	rdataset->rdlist.node = NULL;
	detachnode(db, &node DNS__DB_FLARG_PASS);
	dns_rdatalist_disassociate(rdataset DNS__DB_FLARG_PASS);
}

static void
bogi_rdataset_clone(dns_rdataset_t *source,
		    dns_rdataset_t *target DNS__DB_FLARG) {
	dns_dbnode_t *node = source->rdlist.node;
	boginode_t *bnode = (boginode_t *)node;
	dns_db_t *db = (dns_db_t *)bnode->db;

	dns_rdatalist_clone(source, target DNS__DB_FLARG_PASS);
	target->rdlist.node = NULL;
	attachnode(db, node, &target->rdlist.node DNS__DB_FLARG_PASS);
}

static dns_rdatasetmethods_t bogi_rdataset_methods = {
	.disassociate = bogi_rdataset_disassociate,
	.first = dns_rdatalist_first,
	.next = dns_rdatalist_next,
	.current = dns_rdatalist_current,
	.clone = bogi_rdataset_clone,
	.count = dns_rdatalist_count,
	.addnoqname = dns_rdatalist_addnoqname,
	.getnoqname = dns_rdatalist_getnoqname,
};

static isc_result_t
bind_rdataset_from_slot_trust(boginode_t *node, size_t slot,
			      dns_rdataset_t *rdataset, dns_trust_t trust) {
	if (rdataset == NULL) {
		return ISC_R_SUCCESS;
	}
	REQUIRE(DNS_RDATASET_VALID(rdataset));
	REQUIRE(!dns_rdataset_isassociated(rdataset));

	dns_rdatalist_tordataset(&node->lists[slot], rdataset);
	rdataset->methods = &bogi_rdataset_methods;
	rdataset->trust = trust;
	rdataset->rdlist.node = NULL;
	dns_db_attachnode((dns_db_t *)node->db, (dns_dbnode_t *)node,
			  &rdataset->rdlist.node);
	return ISC_R_SUCCESS;
}

static isc_result_t
bind_rdataset_from_slot(boginode_t *node, size_t slot,
			dns_rdataset_t *rdataset) {
	return bind_rdataset_from_slot_trust(node, slot, rdataset,
					     dns_trust_authanswer);
}

/* Give node to caller, or drop find's ref while rdataset keeps it alive. */
static void
finish_node(dns_db_t *db, boginode_t *node, dns_dbnode_t **nodep,
	    dns_rdataset_t *rdataset) {
	if (nodep != NULL) {
		*nodep = (dns_dbnode_t *)node;
		return;
	}
	if (rdataset != NULL && dns_rdataset_isassociated(rdataset)) {
		dns_dbnode_t *tmp = (dns_dbnode_t *)node;
		dns_db_detachnode(db, &tmp);
		return;
	}
	node_destroy(node);
}

/* Parent owner string: "a.b.example." → "b.example."; origin → fail. */
static int
parent_owner(const char *owner, const char *origin, char *out, size_t outsz) {
	const char *dot;

	if (owner == NULL || origin == NULL || strcmp(owner, origin) == 0) {
		return -1;
	}
	dot = strchr(owner, '.');
	if (dot == NULL || dot[1] == '\0') {
		return -1;
	}
	if (strlen(dot + 1) + 1 > outsz) {
		return -1;
	}
	(void)snprintf(out, outsz, "%s", dot + 1);
	return 0;
}

/* True if owner == origin or owner is a subdomain of origin. */
static bool
owner_in_zone(const char *owner, const char *origin) {
	size_t ol, orl;

	if (owner == NULL || origin == NULL || owner[0] == '\0') {
		return false;
	}
	if (strcmp(owner, origin) == 0) {
		return true;
	}
	ol = strlen(owner);
	orl = strlen(origin);
	if (ol <= orl) {
		return false;
	}
	if (strcmp(owner + (ol - orl), origin) != 0) {
		return false;
	}
	return owner[ol - orl - 1] == '.';
}

static bool
group_has_ns(const Bogi23OwnerGroup *group) {
	size_t i;
	for (i = 0; i < group->count; i++) {
		if (group->sets[i].rrtype != NULL &&
		    strcmp(group->sets[i].rrtype, "NS") == 0) {
			return true;
		}
	}
	return false;
}

/* True if owner exists and carries NS (temporary node; always destroyed). */
static bool
owner_has_ns(bogidb_t *bogi, const char *owner) {
	dns_fixedname_t fixed;
	dns_name_t *nname = dns_fixedname_initname(&fixed);
	isc_buffer_t buf;
	isc_result_t result;
	boginode_t *node;
	bool has;

	isc_buffer_constinit(&buf, owner, strlen(owner));
	isc_buffer_add(&buf, strlen(owner));
	result = dns_name_fromtext(nname, &buf, dns_rootname, 0, NULL);
	if (result != ISC_R_SUCCESS) {
		return false;
	}
	node = node_create(bogi, nname);
	result = node_load_group(node);
	if (result != ISC_R_SUCCESS) {
		node_destroy(node);
		return false;
	}
	has = node->loaded && group_has_ns(&node->group);
	node_destroy(node);
	return has;
}

/*
 * BIND ignores NS RRsets that sit strictly below an existing zone cut in the
 * same zone: those names are in a delegated subtree, so they do not create a
 * deeper cut. Return true if some proper ancestor of `name` (excluding apex)
 * already has NS.
 */
static bool
ancestor_cut_exists(bogidb_t *bogi, const char *name) {
	char cur[DNS_NAME_FORMATSIZE];
	char parent[DNS_NAME_FORMATSIZE];
	const char *origin = bogi->reader.origin;

	if (parent_owner(name, origin, parent, sizeof(parent)) != 0) {
		return false;
	}
	(void)snprintf(cur, sizeof(cur), "%s", parent);
	while (strcmp(cur, origin) != 0) {
		if (owner_has_ns(bogi, cur)) {
			return true;
		}
		if (parent_owner(cur, origin, parent, sizeof(parent)) != 0) {
			break;
		}
		(void)snprintf(cur, sizeof(cur), "%s", parent);
	}
	return false;
}

/*
 * Deepest *effective* zone cut at or above qowner (excluding apex).
 * NS names that lie strictly below another cut are skipped (BIND-compatible).
 */
static isc_result_t
find_zone_cut(bogidb_t *bogi, const char *qowner, boginode_t **cut_nodep,
	      dns_name_t *foundname) {
	char cur[DNS_NAME_FORMATSIZE];
	char parent[DNS_NAME_FORMATSIZE];
	const char *origin = bogi->reader.origin;

	REQUIRE(cut_nodep != NULL && *cut_nodep == NULL);

	if (!owner_in_zone(qowner, origin)) {
		return ISC_R_NOTFOUND;
	}

	if (snprintf(cur, sizeof(cur), "%s", qowner) >= (int)sizeof(cur)) {
		return ISC_R_NOSPACE;
	}

	while (strcmp(cur, origin) != 0) {
		dns_fixedname_t fixed;
		dns_name_t *nname = dns_fixedname_initname(&fixed);
		isc_buffer_t buf;
		isc_result_t result;
		boginode_t *node;

		if (!owner_in_zone(cur, origin) || cur[0] == '\0') {
			break;
		}

		isc_buffer_constinit(&buf, cur, strlen(cur));
		isc_buffer_add(&buf, strlen(cur));
		result = dns_name_fromtext(nname, &buf, dns_rootname, 0, NULL);
		if (result != ISC_R_SUCCESS) {
			return ISC_R_NOTFOUND;
		}

		node = node_create(bogi, nname);
		result = node_load_group(node);
		if (result != ISC_R_SUCCESS) {
			node_destroy(node);
			return result;
		}
		if (node->loaded && group_has_ns(&node->group) &&
		    !ancestor_cut_exists(bogi, cur)) {
			if (foundname != NULL) {
				dns_name_copy(node->name, foundname);
			}
			*cut_nodep = node;
			return ISC_R_SUCCESS;
		}
		node_destroy(node);

		if (parent_owner(cur, origin, parent, sizeof(parent)) != 0) {
			break;
		}
		(void)snprintf(cur, sizeof(cur), "%s", parent);
	}
	return ISC_R_NOTFOUND;
}

static isc_result_t
find(dns_db_t *db, const dns_name_t *name, dns_dbversion_t *version,
     dns_rdatatype_t type, unsigned int options, isc_stdtime_t now,
     dns_dbnode_t **nodep, dns_name_t *foundname, dns_rdataset_t *rdataset,
     dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	bogidb_t *bogi = (bogidb_t *)db;
	boginode_t *node = NULL;
	boginode_t *cut = NULL;
	size_t slot = 0;
	isc_result_t result;
	char qowner[DNS_NAME_FORMATSIZE];

	REQUIRE(VALID_BOGIDB(bogi));
	UNUSED(version);
	UNUSED(now);
	UNUSED(sigrdataset);

	if (nodep != NULL && *nodep != NULL) {
		return ISC_R_FAILURE;
	}

	owner_from_name(name, qowner, sizeof(qowner));

	/* Out-of-zone names (glue targets, etc.): never ISC_R_FAILURE. */
	if (!owner_in_zone(qowner, bogi->reader.origin)) {
		return ISC_R_NOTFOUND;
	}

	/*
	 * Authoritative zone cuts: any NS at/above qname (except apex) is a
	 * delegation — unless GLUEOK (additional-section glue lookup) or
	 * NOZONECUT. Matches sdlz/qpzone: GLUEOK skips the cut so in-bailiwick
	 * A/AAAA at/under the cut can be returned as glue.
	 */
	if ((options & DNS_DBFIND_NOZONECUT) == 0 &&
	    (options & DNS_DBFIND_GLUEOK) == 0) {
		result = find_zone_cut(bogi, qowner, &cut, foundname);
		if (result == ISC_R_SUCCESS) {
			result = materialize_type(cut, dns_rdatatype_ns, &slot);
			if (result != ISC_R_SUCCESS) {
				log_error("bogi find cut NS materialize=%d",
					  (int)result);
				node_destroy(cut);
				return result;
			}
			result = bind_rdataset_from_slot_trust(
				cut, slot, rdataset, dns_trust_authauthority);
			if (result != ISC_R_SUCCESS) {
				log_error("bogi find cut bind NS=%d",
					  (int)result);
				node_destroy(cut);
				return result;
			}
			finish_node(db, cut, nodep, rdataset);
			return DNS_R_DELEGATION;
		}
		if (result != ISC_R_NOTFOUND) {
			log_error("bogi find_zone_cut q=%s err=%d", qowner,
				  (int)result);
			return result;
		}
	}

	node = node_create(bogi, name);
	result = node_load_group(node);
	if (result != ISC_R_SUCCESS) {
		node_destroy(node);
		return result;
	}

	if (!node->loaded) {
		int exists = 0;
		if (bogi23_node_exists(&bogi->reader, node->owner, &exists) !=
			    0 ||
		    !exists) {
			node_destroy(node);
			return DNS_R_NXDOMAIN;
		}
		/* Empty non-terminal */
		if (foundname != NULL) {
			dns_name_copy(name, foundname);
		}
		finish_node(db, node, nodep, NULL);
		return DNS_R_NXRRSET;
	}

	if (foundname != NULL) {
		dns_name_copy(name, foundname);
	}

	/* CNAME synthesis when asking for non-CNAME */
	if (type != dns_rdatatype_cname && type != dns_rdatatype_any) {
		size_t ci;
		for (ci = 0; ci < node->group.count; ci++) {
			if (node->group.sets[ci].rrtype != NULL &&
			    strcmp(node->group.sets[ci].rrtype, "CNAME") == 0) {
				result = materialize_type(node,
							  dns_rdatatype_cname,
							  &slot);
				if (result != ISC_R_SUCCESS) {
					node_destroy(node);
					return result;
				}
				CHECK(bind_rdataset_from_slot(node, slot,
							      rdataset));
				finish_node(db, node, nodep, rdataset);
				return DNS_R_CNAME;
			}
		}
	}

	if (type == dns_rdatatype_any) {
		/*
		 * BIND ANY path: findext leaves rdataset unassociated;
		 * answers come from allrdatasets().
		 */
		finish_node(db, node, nodep, NULL);
		return ISC_R_SUCCESS;
	}

	result = materialize_type(node, type, &slot);

	if (result == DNS_R_NXRRSET) {
		finish_node(db, node, nodep, NULL);
		return DNS_R_NXRRSET;
	}
	if (result != ISC_R_SUCCESS) {
		node_destroy(node);
		return result;
	}

	CHECK(bind_rdataset_from_slot(node, slot, rdataset));
	finish_node(db, node, nodep, rdataset);

	/*
	 * Match qpzone: GLUEOK finds beneath a zone cut are DNS_R_GLUE
	 * (trust glue). Sibling auth data remains ISC_R_SUCCESS. Referral
	 * additional uses addglue(), which only emits DNS_R_GLUE — so
	 * out-of-bailiwick sibling A/AAAA are not stuffed into ADDITIONAL.
	 */
	if ((options & DNS_DBFIND_GLUEOK) != 0) {
		boginode_t *gcut = NULL;
		isc_result_t gr = find_zone_cut(bogi, qowner, &gcut, NULL);
		if (gr == ISC_R_SUCCESS) {
			node_destroy(gcut);
			if (rdataset != NULL &&
			    dns_rdataset_isassociated(rdataset)) {
				rdataset->trust = dns_trust_glue;
			}
			return DNS_R_GLUE;
		}
	}
	return ISC_R_SUCCESS;

cleanup:
	node_destroy(node);
	return result;
}

static isc_result_t
findzonecut(dns_db_t *db, const dns_name_t *name, unsigned int options,
	    isc_stdtime_t now, dns_dbnode_t **nodep, dns_name_t *foundname,
	    dns_name_t *dcname, dns_rdataset_t *rdataset,
	    dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	bogidb_t *bogi = (bogidb_t *)db;
	boginode_t *cut = NULL;
	char qowner[DNS_NAME_FORMATSIZE];
	size_t slot = 0;
	isc_result_t result;

	REQUIRE(VALID_BOGIDB(bogi));
	UNUSED(options);
	UNUSED(now);
	UNUSED(sigrdataset);

	if (nodep != NULL && *nodep != NULL) {
		return ISC_R_FAILURE;
	}

	owner_from_name(name, qowner, sizeof(qowner));
	if (!owner_in_zone(qowner, bogi->reader.origin)) {
		return ISC_R_NOTFOUND;
	}
	result = find_zone_cut(bogi, qowner, &cut, foundname);
	if (result == ISC_R_NOTFOUND) {
		return ISC_R_NOTFOUND;
	}
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	if (dcname != NULL) {
		dns_name_copy(cut->name, dcname);
	}
	result = materialize_type(cut, dns_rdatatype_ns, &slot);
	if (result != ISC_R_SUCCESS) {
		node_destroy(cut);
		return result;
	}
	result = bind_rdataset_from_slot_trust(cut, slot, rdataset,
					       dns_trust_authauthority);
	if (result != ISC_R_SUCCESS) {
		node_destroy(cut);
		return result;
	}
	finish_node(db, cut, nodep, rdataset);
	return ISC_R_SUCCESS;
}

static void
attachnode(dns_db_t *db, dns_dbnode_t *source,
	   dns_dbnode_t **targetp DNS__DB_FLARG) {
	boginode_t *node = (boginode_t *)source;
	UNUSED(db);
	REQUIRE(VALID_NODE(node));
	REQUIRE(targetp != NULL && *targetp == NULL);
	isc_refcount_increment(&node->references);
	*targetp = source;
}

static void
detachnode(dns_db_t *db, dns_dbnode_t **targetp DNS__DB_FLARG) {
	boginode_t *node;
	UNUSED(db);
	REQUIRE(targetp != NULL && *targetp != NULL);
	node = (boginode_t *)*targetp;
	REQUIRE(VALID_NODE(node));
	*targetp = NULL;
	if (isc_refcount_decrement(&node->references) == 1) {
		node_destroy(node);
	}
}

typedef struct bogi_dbiter {
	dns_dbiterator_t common;
	char **owners;
	size_t *owner_lens;
	size_t count;
	size_t cap;
	size_t index;
	bool have_cursor;
} bogi_dbiter_t;

typedef struct bogi_collect_ctx {
	bogidb_t *bogi;
	bogi_dbiter_t *it;
	isc_result_t error;
} bogi_collect_ctx_t;

static void
dbiter_free_owners(bogi_dbiter_t *it) {
	dns_db_t *db;
	size_t i;

	if (it == NULL || it->owners == NULL) {
		return;
	}
	db = it->common.db;
	for (i = 0; i < it->count; i++) {
		if (it->owners[i] != NULL) {
			isc_mem_put(db->mctx, it->owners[i],
				    it->owner_lens[i] + 1);
			it->owners[i] = NULL;
		}
	}
	if (it->cap > 0) {
		isc_mem_cput(db->mctx, it->owners, it->cap, sizeof(char *));
		isc_mem_cput(db->mctx, it->owner_lens, it->cap, sizeof(size_t));
	}
	it->owners = NULL;
	it->owner_lens = NULL;
	it->count = 0;
	it->cap = 0;
}

static int
collect_owner_cb(Bogi23Reader *reader, const void *groupv, void *arg) {
	bogi_collect_ctx_t *ctx = (bogi_collect_ctx_t *)arg;
	bogi_dbiter_t *it = ctx->it;
	const Bogi23OwnerGroup *group = (const Bogi23OwnerGroup *)groupv;
	char *copy;
	size_t len;

	UNUSED(reader);
	if (ctx->error != ISC_R_SUCCESS) {
		return -1;
	}
	if (group == NULL || group->owner == NULL) {
		return 0;
	}
	if (it->count == it->cap) {
		size_t ncap = it->cap == 0 ? 1024 : it->cap * 2;
		char **nown = isc_mem_cget(it->common.db->mctx, ncap,
					   sizeof(char *));
		size_t *nlens = isc_mem_cget(it->common.db->mctx, ncap,
					     sizeof(size_t));
		if (it->owners != NULL) {
			memmove(nown, it->owners, it->count * sizeof(char *));
			memmove(nlens, it->owner_lens,
				it->count * sizeof(size_t));
			isc_mem_cput(it->common.db->mctx, it->owners, it->cap,
				     sizeof(char *));
			isc_mem_cput(it->common.db->mctx, it->owner_lens,
				     it->cap, sizeof(size_t));
		}
		it->owners = nown;
		it->owner_lens = nlens;
		it->cap = ncap;
	}
	len = strlen(group->owner);
	copy = isc_mem_get(it->common.db->mctx, len + 1);
	memcpy(copy, group->owner, len + 1);
	it->owners[it->count] = copy;
	it->owner_lens[it->count] = len;
	it->count++;
	return 0;
}

static void
dbiterator_destroy(dns_dbiterator_t **iteratorp DNS__DB_FLARG) {
	bogi_dbiter_t *it;
	dns_db_t *db;
	isc_mem_t *mctx;

	REQUIRE(iteratorp != NULL && *iteratorp != NULL);
	it = (bogi_dbiter_t *)(*iteratorp);
	db = it->common.db;
	mctx = db->mctx;
	dbiter_free_owners(it);
	dns_db_detach(&it->common.db);
	isc_mem_put(mctx, it, sizeof(*it));
	*iteratorp = NULL;
}

static isc_result_t
dbiterator_first(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	bogi_dbiter_t *it = (bogi_dbiter_t *)iterator;

	if (it->count == 0) {
		it->have_cursor = false;
		return ISC_R_NOMORE;
	}
	it->index = 0;
	it->have_cursor = true;
	return ISC_R_SUCCESS;
}

static isc_result_t
dbiterator_last(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	bogi_dbiter_t *it = (bogi_dbiter_t *)iterator;

	if (it->count == 0) {
		it->have_cursor = false;
		return ISC_R_NOMORE;
	}
	it->index = it->count - 1;
	it->have_cursor = true;
	return ISC_R_SUCCESS;
}

static isc_result_t
dbiterator_seek(dns_dbiterator_t *iterator,
		const dns_name_t *name DNS__DB_FLARG) {
	bogi_dbiter_t *it = (bogi_dbiter_t *)iterator;
	char owner[DNS_NAME_FORMATSIZE];
	size_t i;

	owner_from_name(name, owner, sizeof(owner));
	for (i = 0; i < it->count; i++) {
		if (strcmp(it->owners[i], owner) == 0) {
			it->index = i;
			it->have_cursor = true;
			return ISC_R_SUCCESS;
		}
	}
	return ISC_R_NOTFOUND;
}

static isc_result_t
dbiterator_seek3(dns_dbiterator_t *iterator, const dns_name_t *name
			 DNS__DB_FLARG) {
	UNUSED(iterator);
	UNUSED(name);
	return ISC_R_NOTIMPLEMENTED;
}

static isc_result_t
dbiterator_prev(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	bogi_dbiter_t *it = (bogi_dbiter_t *)iterator;

	REQUIRE(it->have_cursor);
	if (it->index == 0) {
		it->have_cursor = false;
		return ISC_R_NOMORE;
	}
	it->index--;
	return ISC_R_SUCCESS;
}

static isc_result_t
dbiterator_next(dns_dbiterator_t *iterator DNS__DB_FLARG) {
	bogi_dbiter_t *it = (bogi_dbiter_t *)iterator;

	REQUIRE(it->have_cursor);
	if (it->index + 1 >= it->count) {
		it->have_cursor = false;
		return ISC_R_NOMORE;
	}
	it->index++;
	return ISC_R_SUCCESS;
}

static isc_result_t
dbiterator_current(dns_dbiterator_t *iterator, dns_dbnode_t **nodep,
		   dns_name_t *name DNS__DB_FLARG) {
	bogi_dbiter_t *it = (bogi_dbiter_t *)iterator;
	bogidb_t *bogi = (bogidb_t *)iterator->db;
	boginode_t *node;
	dns_fixedname_t fixed;
	dns_name_t *nname = dns_fixedname_initname(&fixed);
	isc_buffer_t buf;
	isc_result_t result;
	const char *owner;

	REQUIRE(it->have_cursor);
	REQUIRE(nodep != NULL && *nodep == NULL);
	owner = it->owners[it->index];

	isc_buffer_constinit(&buf, owner, strlen(owner));
	isc_buffer_add(&buf, strlen(owner));
	result = dns_name_fromtext(nname, &buf, dns_rootname, 0, NULL);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	node = node_create(bogi, nname);
	result = node_load_group(node);
	if (result != ISC_R_SUCCESS) {
		node_destroy(node);
		return result;
	}
	node->exists = node->loaded;
	if (name != NULL) {
		dns_name_copy(node->name, name);
	}
	attachnode(iterator->db, (dns_dbnode_t *)node, nodep DNS__DB_FLARG_PASS);
	/* attachnode increments; drop create ref so nodep holds one. */
	{
		dns_dbnode_t *tmp = (dns_dbnode_t *)node;
		detachnode(iterator->db, &tmp DNS__DB_FLARG_PASS);
	}
	return ISC_R_SUCCESS;
}

static isc_result_t
dbiterator_pause(dns_dbiterator_t *iterator) {
	UNUSED(iterator);
	return ISC_R_SUCCESS;
}

static isc_result_t
dbiterator_origin(dns_dbiterator_t *iterator, dns_name_t *name) {
	UNUSED(iterator);
	dns_name_copy(dns_rootname, name);
	return ISC_R_SUCCESS;
}

static dns_dbiteratormethods_t bogi_dbiterator_methods = {
	dbiterator_destroy, dbiterator_first,	  dbiterator_last,
	dbiterator_seek,    dbiterator_seek3,	  dbiterator_prev,
	dbiterator_next,    dbiterator_current, dbiterator_pause,
	dbiterator_origin
};

static isc_result_t
createiterator(dns_db_t *db, unsigned int options,
	       dns_dbiterator_t **iteratorp) {
	bogidb_t *bogi = (bogidb_t *)db;
	bogi_dbiter_t *it;
	bogi_collect_ctx_t ctx;
	int walk_rc;
	size_t i, origin_idx = (size_t)-1;

	REQUIRE(VALID_BOGIDB(bogi));
	REQUIRE(iteratorp != NULL && *iteratorp == NULL);

	if ((options & DNS_DB_NSEC3ONLY) != 0 ||
	    (options & DNS_DB_NONSEC3) != 0) {
		return ISC_R_NOTIMPLEMENTED;
	}

	it = isc_mem_get(db->mctx, sizeof(*it));
	*it = (bogi_dbiter_t){
		.common.methods = &bogi_dbiterator_methods,
		.common.magic = DNS_DBITERATOR_MAGIC,
		.common.relative_names =
			((options & DNS_DB_RELATIVENAMES) != 0),
		.have_cursor = false,
	};
	dns_db_attach(db, &it->common.db);

	log_info("bogi createiterator: foreach begin origin=%s",
		 bogi->reader.origin);
	ctx = (bogi_collect_ctx_t){
		.bogi = bogi, .it = it, .error = ISC_R_SUCCESS
	};
	walk_rc = bogi23_foreach_owner(&bogi->reader, collect_owner_cb, &ctx);
	log_info("bogi createiterator: foreach rc=%d err=%d count=%zu", walk_rc,
		 (int)ctx.error, it->count);
	if (walk_rc != 0 || ctx.error != ISC_R_SUCCESS) {
		dns_dbiterator_t *tmp = &it->common;
		dbiterator_destroy(&tmp DNS__DB_FILELINE);
		return ISC_R_FAILURE;
	}

	/* Prefer apex first (AXFR SOA-at-start convention). */
	for (i = 0; i < it->count; i++) {
		if (strcmp(it->owners[i], bogi->reader.origin) == 0) {
			origin_idx = i;
			break;
		}
	}
	if (origin_idx != (size_t)-1 && origin_idx != 0) {
		char *o = it->owners[origin_idx];
		size_t ol = it->owner_lens[origin_idx];
		memmove(&it->owners[1], &it->owners[0],
			origin_idx * sizeof(char *));
		memmove(&it->owner_lens[1], &it->owner_lens[0],
			origin_idx * sizeof(size_t));
		it->owners[0] = o;
		it->owner_lens[0] = ol;
	}

	*iteratorp = (dns_dbiterator_t *)it;
	return ISC_R_SUCCESS;
}

typedef struct bogi_rditer {
	dns_rdatasetiter_t common;
	size_t index;
} bogi_rditer_t;

static void
rditer_destroy(dns_rdatasetiter_t **iteratorp DNS__DB_FLARG) {
	bogi_rditer_t *it;
	dns_db_t *db;
	dns_dbnode_t *node;
	isc_mem_t *mctx;

	REQUIRE(iteratorp != NULL && *iteratorp != NULL);
	it = (bogi_rditer_t *)(*iteratorp);
	db = it->common.db;
	node = it->common.node;
	mctx = db->mctx;
	dns_db_detachnode(db, &node DNS__DB_FLARG_PASS);
	dns_db_detach(&db);
	isc_mem_put(mctx, it, sizeof(*it));
	*iteratorp = NULL;
}

static isc_result_t
rditer_first(dns_rdatasetiter_t *iterator DNS__DB_FLARG) {
	bogi_rditer_t *it = (bogi_rditer_t *)iterator;
	boginode_t *node = (boginode_t *)iterator->node;
	isc_result_t result;

	result = node_load_group(node);
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	if (!node->loaded || node->group.count == 0) {
		return ISC_R_NOMORE;
	}
	it->index = 0;
	return ISC_R_SUCCESS;
}

static isc_result_t
rditer_next(dns_rdatasetiter_t *iterator DNS__DB_FLARG) {
	bogi_rditer_t *it = (bogi_rditer_t *)iterator;
	boginode_t *node = (boginode_t *)iterator->node;

	it->index++;
	if (it->index >= node->group.count) {
		return ISC_R_NOMORE;
	}
	return ISC_R_SUCCESS;
}

static void
rditer_current(dns_rdatasetiter_t *iterator,
	       dns_rdataset_t *rdataset DNS__DB_FLARG) {
	bogi_rditer_t *it = (bogi_rditer_t *)iterator;
	boginode_t *node = (boginode_t *)iterator->node;
	dns_rdatatype_t type = 0;
	size_t slot = 0;
	isc_result_t result;

	REQUIRE(it->index < node->group.count);
	result = rrtype_to_dns(node->group.sets[it->index].rrtype, &type);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
	result = materialize_type(node, type, &slot);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
	result = bind_rdataset_from_slot(node, slot, rdataset);
	RUNTIME_CHECK(result == ISC_R_SUCCESS);
}

static dns_rdatasetitermethods_t bogi_rditer_methods = {
	.destroy = rditer_destroy,
	.first = rditer_first,
	.next = rditer_next,
	.current = rditer_current,
};

static isc_result_t
findrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     dns_rdatatype_t type, dns_rdatatype_t covers, isc_stdtime_t now,
	     dns_rdataset_t *rdataset,
	     dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	boginode_t *bnode = (boginode_t *)node;
	size_t slot = 0;
	isc_result_t result;

	REQUIRE(VALID_BOGIDB((bogidb_t *)db));
	REQUIRE(VALID_NODE(bnode));
	UNUSED(version);
	UNUSED(covers);
	UNUSED(now);
	UNUSED(sigrdataset);

	result = materialize_type(bnode, type, &slot);
	if (result == DNS_R_NXRRSET || result == DNS_R_NXDOMAIN) {
		/* BIND zone load treats missing NSEC3PARAM as ISC_R_NOTFOUND. */
		return ISC_R_NOTFOUND;
	}
	if (result != ISC_R_SUCCESS) {
		return result;
	}
	return bind_rdataset_from_slot(bnode, slot, rdataset);
}

static isc_result_t
allrdatasets(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	     unsigned int options, isc_stdtime_t now,
	     dns_rdatasetiter_t **iteratorp DNS__DB_FLARG) {
	bogi_rditer_t *it;
	boginode_t *bnode = (boginode_t *)node;
	isc_result_t result;

	REQUIRE(VALID_BOGIDB((bogidb_t *)db));
	REQUIRE(VALID_NODE(bnode));
	REQUIRE(iteratorp != NULL && *iteratorp == NULL);
	UNUSED(version);
	UNUSED(options);
	UNUSED(now);

	result = node_load_group(bnode);
	if (result != ISC_R_SUCCESS) {
		return result;
	}

	it = isc_mem_get(db->mctx, sizeof(*it));
	*it = (bogi_rditer_t){
		.common.magic = DNS_RDATASETITER_MAGIC,
		.common.methods = &bogi_rditer_methods,
		.common.now = now,
		.common.options = options,
		.index = 0,
	};
	dns_db_attach(db, &it->common.db);
	dns_db_attachnode(db, node, &it->common.node);
	*iteratorp = (dns_rdatasetiter_t *)it;
	return ISC_R_SUCCESS;
}

static isc_result_t
addrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	    isc_stdtime_t now, dns_rdataset_t *rdataset, unsigned int options,
	    dns_rdataset_t *addedrdataset DNS__DB_FLARG) {
	UNUSED(db);
	UNUSED(node);
	UNUSED(version);
	UNUSED(now);
	UNUSED(rdataset);
	UNUSED(options);
	UNUSED(addedrdataset);
	return ISC_R_NOPERM;
}

static isc_result_t
subtractrdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
		 dns_rdataset_t *rdataset, unsigned int options,
		 dns_rdataset_t *newrdataset DNS__DB_FLARG) {
	UNUSED(db);
	UNUSED(node);
	UNUSED(version);
	UNUSED(rdataset);
	UNUSED(options);
	UNUSED(newrdataset);
	return ISC_R_NOPERM;
}

static isc_result_t
deleterdataset(dns_db_t *db, dns_dbnode_t *node, dns_dbversion_t *version,
	       dns_rdatatype_t type, dns_rdatatype_t covers DNS__DB_FLARG) {
	UNUSED(db);
	UNUSED(node);
	UNUSED(version);
	UNUSED(type);
	UNUSED(covers);
	return ISC_R_NOPERM;
}

static bool
issecure(dns_db_t *db) {
	UNUSED(db);
	return false;
}

static unsigned int
nodecount(dns_db_t *db, dns_dbtree_t tree) {
	bogidb_t *bogi = (bogidb_t *)db;
	UNUSED(tree);
	REQUIRE(VALID_BOGIDB(bogi));
	return (unsigned int)bogi->reader.owner_count;
}

static void
setloop(dns_db_t *db, isc_loop_t *loop) {
	UNUSED(db);
	UNUSED(loop);
}

static isc_result_t
getoriginnode(dns_db_t *db, dns_dbnode_t **nodep DNS__DB_FLARG) {
	bogidb_t *bogi = (bogidb_t *)db;
	REQUIRE(VALID_BOGIDB(bogi));
	return findnode(db, &bogi->common.origin, true,
			nodep DNS__DB_FLARG_PASS);
}

static isc_result_t
getnsec3parameters(dns_db_t *db, dns_dbversion_t *version, dns_hash_t *hash,
		  uint8_t *flags, uint16_t *iterations, unsigned char *salt,
		  size_t *salt_len) {
	UNUSED(db);
	UNUSED(version);
	UNUSED(hash);
	UNUSED(flags);
	UNUSED(iterations);
	UNUSED(salt);
	UNUSED(salt_len);
	return ISC_R_NOTFOUND;
}

static isc_result_t
findnsec3node(dns_db_t *db, const dns_name_t *name, bool create,
	      dns_dbnode_t **nodep DNS__DB_FLARG) {
	UNUSED(db);
	UNUSED(name);
	UNUSED(create);
	UNUSED(nodep);
	return ISC_R_NOTFOUND;
}

static isc_result_t
setsigningtime(dns_db_t *db, dns_rdataset_t *rdataset, isc_stdtime_t resign) {
	UNUSED(db);
	UNUSED(rdataset);
	UNUSED(resign);
	return ISC_R_SUCCESS;
}

static isc_result_t
getsigningtime(dns_db_t *db, isc_stdtime_t *resign, dns_name_t *name,
	       dns_typepair_t *typepair) {
	UNUSED(db);
	UNUSED(resign);
	UNUSED(name);
	UNUSED(typepair);
	return ISC_R_NOTFOUND;
}

static dns_stats_t *
getrrsetstats(dns_db_t *db) {
	UNUSED(db);
	return NULL;
}

static isc_result_t
findnodeext(dns_db_t *db, const dns_name_t *name, bool create,
	    dns_clientinfomethods_t *methods, dns_clientinfo_t *clientinfo,
	    dns_dbnode_t **nodep DNS__DB_FLARG) {
	UNUSED(methods);
	UNUSED(clientinfo);
	return findnode(db, name, create, nodep DNS__DB_FLARG_PASS);
}

static isc_result_t
findext(dns_db_t *db, const dns_name_t *name, dns_dbversion_t *version,
	dns_rdatatype_t type, unsigned int options, isc_stdtime_t now,
	dns_dbnode_t **nodep, dns_name_t *foundname,
	dns_clientinfomethods_t *methods, dns_clientinfo_t *clientinfo,
	dns_rdataset_t *rdataset,
	dns_rdataset_t *sigrdataset DNS__DB_FLARG) {
	UNUSED(methods);
	UNUSED(clientinfo);
	return find(db, name, version, type, options, now, nodep, foundname,
		    rdataset, sigrdataset DNS__DB_FLARG_PASS);
}

static isc_result_t
setcachestats(dns_db_t *db, isc_stats_t *stats) {
	UNUSED(db);
	UNUSED(stats);
	return ISC_R_SUCCESS;
}

static isc_result_t
nodefullname(dns_db_t *db, dns_dbnode_t *node, dns_name_t *name) {
	boginode_t *bnode = (boginode_t *)node;
	UNUSED(db);
	REQUIRE(VALID_NODE(bnode));
	dns_name_copy(bnode->name, name);
	return ISC_R_SUCCESS;
}

/*
 * Like qpzone addglue: only attach A/AAAA that find() returns as DNS_R_GLUE
 * (in-bailiwick under a cut). Always return SUCCESS so named does not fall
 * through to query_additional_cb (which would add sibling auth A/AAAA).
 */
static isc_result_t
addglue(dns_db_t *db, dns_dbversion_t *version, dns_rdataset_t *rdataset,
	dns_message_t *msg) {
	isc_result_t result;

	REQUIRE(VALID_BOGIDB((bogidb_t *)db));
	REQUIRE(rdataset != NULL);
	REQUIRE(rdataset->type == dns_rdatatype_ns);
	REQUIRE(msg != NULL);
	UNUSED(version);

	for (result = dns_rdataset_first(rdataset); result == ISC_R_SUCCESS;
	     result = dns_rdataset_next(rdataset))
	{
		dns_rdata_t rdata = DNS_RDATA_INIT;
		dns_rdata_ns_t ns;
		dns_fixedname_t fixed;
		dns_name_t *fname = NULL;
		dns_dbnode_t *node = NULL;
		dns_rdataset_t found_a, found_aaaa;
		dns_name_t *msgname = NULL;
		dns_rdataset_t *msga = NULL, *msgaaaa = NULL;
		isc_result_t fr;
		bool have = false;

		dns_rdataset_current(rdataset, &rdata);
		if (dns_rdata_tostruct(&rdata, &ns, NULL) != ISC_R_SUCCESS) {
			continue;
		}

		fname = dns_fixedname_initname(&fixed);
		dns_rdataset_init(&found_a);
		dns_rdataset_init(&found_aaaa);

		fr = find(db, &ns.name, version, dns_rdatatype_a,
			  DNS_DBFIND_GLUEOK, 0, &node, fname, &found_a,
			  NULL DNS__DB_FLARG_PASS);
		if (fr == DNS_R_GLUE && dns_rdataset_isassociated(&found_a)) {
			have = true;
		} else {
			if (dns_rdataset_isassociated(&found_a)) {
				dns_rdataset_disassociate(&found_a);
			}
			if (node != NULL) {
				detachnode(db, &node DNS__DB_FLARG_PASS);
			}
			node = NULL;
		}

		{
			dns_dbnode_t *node6 = NULL;
			dns_fixedname_t fixed6;
			dns_name_t *fname6 = dns_fixedname_initname(&fixed6);
			fr = find(db, &ns.name, version, dns_rdatatype_aaaa,
				  DNS_DBFIND_GLUEOK, 0, &node6, fname6,
				  &found_aaaa, NULL DNS__DB_FLARG_PASS);
			if (fr == DNS_R_GLUE &&
			    dns_rdataset_isassociated(&found_aaaa)) {
				have = true;
				if (node == NULL) {
					dns_name_copy(fname6, fname);
					node = node6;
					node6 = NULL;
				}
			} else if (dns_rdataset_isassociated(&found_aaaa)) {
				dns_rdataset_disassociate(&found_aaaa);
			}
			if (node6 != NULL) {
				detachnode(db, &node6 DNS__DB_FLARG_PASS);
			}
		}

		if (have) {
			boginode_t *ns_owner = (boginode_t *)rdataset->rdlist
						       .node;
			bool in_bailiwick = false;

			if (ns_owner != NULL && VALID_NODE(ns_owner)) {
				in_bailiwick = dns_name_issubdomain(
					&ns.name, ns_owner->name);
			}

			dns_message_gettempname(msg, &msgname);
			dns_name_copy(fname, msgname);
			if (dns_rdataset_isassociated(&found_a)) {
				dns_message_gettemprdataset(msg, &msga);
				dns_rdataset_clone(&found_a, msga);
				if (in_bailiwick) {
					msga->attributes |=
						DNS_RDATASETATTR_REQUIRED;
				}
				ISC_LIST_APPEND(msgname->list, msga, link);
			}
			if (dns_rdataset_isassociated(&found_aaaa)) {
				dns_message_gettemprdataset(msg, &msgaaaa);
				dns_rdataset_clone(&found_aaaa, msgaaaa);
				if (in_bailiwick) {
					msgaaaa->attributes |=
						DNS_RDATASETATTR_REQUIRED;
				}
				ISC_LIST_APPEND(msgname->list, msgaaaa, link);
			}
			dns_message_addname(msg, msgname,
					    DNS_SECTION_ADDITIONAL);
		}

		if (dns_rdataset_isassociated(&found_a)) {
			dns_rdataset_disassociate(&found_a);
		}
		if (dns_rdataset_isassociated(&found_aaaa)) {
			dns_rdataset_disassociate(&found_aaaa);
		}
		if (node != NULL) {
			detachnode(db, &node DNS__DB_FLARG_PASS);
		}
		dns_rdata_freestruct(&ns);
	}

	return ISC_R_SUCCESS;
}

static dns_dbmethods_t bogidb_methods = {
	.destroy = destroy,
	.currentversion = currentversion,
	.newversion = newversion,
	.attachversion = attachversion,
	.closeversion = closeversion,
	.findnode = findnode,
	.find = find,
	.findzonecut = findzonecut,
	.attachnode = attachnode,
	.detachnode = detachnode,
	.createiterator = createiterator,
	.findrdataset = findrdataset,
	.allrdatasets = allrdatasets,
	.addrdataset = addrdataset,
	.subtractrdataset = subtractrdataset,
	.deleterdataset = deleterdataset,
	.issecure = issecure,
	.nodecount = nodecount,
	.setloop = setloop,
	.getoriginnode = getoriginnode,
	.getnsec3parameters = getnsec3parameters,
	.findnsec3node = findnsec3node,
	.setsigningtime = setsigningtime,
	.getsigningtime = getsigningtime,
	.getrrsetstats = getrrsetstats,
	.findnodeext = findnodeext,
	.findext = findext,
	.setcachestats = setcachestats,
	.nodefullname = nodefullname,
	.addglue = addglue,
};

isc_result_t
create_db(isc_mem_t *mctx, const dns_name_t *origin, dns_dbtype_t type,
	  dns_rdataclass_t rdclass, unsigned int argc, char *argv[],
	  void *driverarg, dns_db_t **dbp) {
	bogidb_t *bogi = NULL;
	bogi_instance_t *inst;
	isc_result_t result = ISC_R_SUCCESS;

	REQUIRE(type == dns_dbtype_zone);
	REQUIRE(rdclass == dns_rdataclass_in);
	REQUIRE(argc == 0);
	REQUIRE(argv != NULL);
	REQUIRE(driverarg != NULL);
	REQUIRE(dbp != NULL && *dbp == NULL);

	inst = (bogi_instance_t *)driverarg;
	REQUIRE(inst->bogi_path != NULL);

	bogi = isc_mem_get(mctx, sizeof(*bogi));
	*bogi = (bogidb_t){
		.common.magic = DNS_DB_MAGIC,
		.common.impmagic = BOGIDB_MAGIC,
		.common.methods = &bogidb_methods,
		.common.rdclass = rdclass,
		.inst = inst,
		.version_token = 1,
	};
	isc_mem_attach(mctx, &bogi->common.mctx);
	dns_name_init(&bogi->common.origin, NULL);
	dns_name_dupwithoffsets(origin, mctx, &bogi->common.origin);
	isc_refcount_init(&bogi->common.references, 1);

	(void)memset(&bogi->reader, 0, sizeof(bogi->reader));
	bogi->reader.fd = -1;
	log_info("bogi mmap-direct create_db path=%s", inst->bogi_path);
	if (bogi23_open(&bogi->reader, inst->bogi_path) != 0) {
		log_error("bogi23_open failed: %s", inst->bogi_path);
		result = ISC_R_FAILURE;
		goto cleanup;
	}
	bogi->reader_open = 1;
	if (bogi23_trace_begin(&bogi->reader) != 0) {
		result = ISC_R_FAILURE;
		goto cleanup;
	}

	log_info("bogi mmap-direct ready origin=%s owners=%llu (no hydrate)",
		 bogi->reader.origin,
		 (unsigned long long)bogi->reader.owner_count);

	*dbp = (dns_db_t *)bogi;
	return ISC_R_SUCCESS;

cleanup:
	if (bogi != NULL) {
		if (bogi->reader_open) {
			bogi23_trace_end(&bogi->reader);
			bogi23_close(&bogi->reader);
		}
		if (dns_name_dynamic(&bogi->common.origin)) {
			dns_name_free(&bogi->common.origin, mctx);
		}
		isc_mem_putanddetach(&bogi->common.mctx, bogi, sizeof(*bogi));
	}
	return result;
}
