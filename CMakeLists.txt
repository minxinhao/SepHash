cmake_minimum_required(VERSION 3.0.2)
SET(CMAKE_CXX_COMPILER "/usr/bin/g++-11")
project(MyIndex)
set(CMAKE_CXX_FLAGS "-O3") # -march=native
# set(CMAKE_CXX_FLAGS "-g -O0") # -march=native
set(CMAKE_CXX_STANDARD 20)

include_directories(
  ${catkin_INCLUDE_DIRS}
  /opt/intel/oneapi/mkl/latest/include
  "./include"
)

link_directories(
  ${catkin_LIB_DIRS}
  /opt/intel/oneapi/mkl/latest/lib/intel64
)

# 现在改为手动编译search.cc为.s，再手动删除vzeroupper后编成.o
# add_library(search OBJECT "src/search.cc")
# set_target_properties(search PROPERTIES COMPILE_FLAGS "-O3 -march=native")

AUX_SOURCE_DIRECTORY ("src" src)

# set(libs "-lmkl_intel_ilp64 -lmkl_sequential -lmkl_core -lpthread -lm -ldl -libverbs -lpthread" )
set(libs "-lpthread -lm -ldl -libverbs -lpthread" )

add_executable(ser_cli test/ser_cli.cc ${src})
target_link_libraries(ser_cli PRIVATE ${libs})

add_executable(ser_cli_var_kv test/ser_cli_var_kv.cc ${src})
target_link_libraries(ser_cli_var_kv PRIVATE ${libs})
