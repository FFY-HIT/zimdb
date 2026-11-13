#define main zimdb_core_main
#include "native_zone.cpp"
#undef main
int main(){
  require(true,"long successful literal diagnostic text");
  require(true,std::string("dynamic successful diagnostic"));
  syscheck(true,"long successful syscall diagnostic text");
  auto capture=[](const std::function<void()>&f){try{f();return std::string("NO_EXCEPTION");}
    catch(const std::runtime_error&e){return std::string("runtime_error:")+e.what();}};
  auto a=capture([]{require(false,"long failed literal diagnostic text");});
  auto b=capture([]{require(false,std::string("dynamic failed diagnostic"));});
  errno=ENOENT;auto c=capture([]{syscheck(false,"failed literal syscall");});
  errno=EACCES;auto d=capture([]{syscheck(false,std::string("failed dynamic syscall"));});
  require(a=="runtime_error:long failed literal diagnostic text","literal failure parity");
  require(b=="runtime_error:dynamic failed diagnostic","dynamic failure parity");
  require(c==std::string("runtime_error:failed literal syscall: ")+std::strerror(ENOENT),"literal syscall parity");
  require(d==std::string("runtime_error:failed dynamic syscall: ")+std::strerror(EACCES),"dynamic syscall parity");
  std::cout<<"{\"literal\":"<<json_string(a)<<",\"dynamic\":"<<json_string(b)<<",\"sys_literal\":"<<json_string(c)<<",\"sys_dynamic\":"<<json_string(d)<<"}\n";
}
