cmake_minimum_required( VERSION 3.30 FATAL_ERROR )

set(
    CMAKE_CXX_FLAGS
    "${CMAKE_CXX_FLAGS} -stdlib=libc++ -Wall -Wextra -pedantic -fno-plt"
)
set(
    CMAKE_EXPERIMENTAL_CXX_IMPORT_STD
    "0e5b6991-d74f-4b3d-a41c-cf096e0b2508"
)

project( asmdiff LANGUAGES C CXX )

set( CMAKE_CXX_MODULE_STD ON )

include( CPM.cmake/cmake/CPM.cmake )

CPMAddPackage(
    "capstone"
    GITHUB_REPOSITORY "capstone-engine/capstone"
    GIT_TAG "next"
    PATCH_COMMAND sh -c "sed -i 's/{CMAKE_SOURCE_DIR/{CMAKE_CURRENT_SOURCE_DIR/g' *.txt"
)
CPMAddPackage( "gh:gregthemadmonk/dot-xx#main" )
CPMAddPackage( "gh:getml/reflect-cpp#main" )

function( add_module_library LIB_NAME )
    string( REPLACE "." "/" LIB_DIR "${LIB_NAME}" )
    string( REPLACE "." "_" LIB_TAR "${LIB_NAME}" )

    file( GLOB_RECURSE LIB_CC "src/${LIB_DIR}/*.cc" )
    file( GLOB_RECURSE LIB_XX "src/${LIB_DIR}/*.xx" )

    set_source_files_properties( ${LIB_XX} PROPERTIES LANGUAGE CXX )

    add_library( "${LIB_NAME}" STATIC ${LIB_CC} )
    target_sources(
        "${LIB_NAME}" PUBLIC
        FILE_SET "${LIB_TAR}_mod"
        TYPE CXX_MODULES
        FILES ${LIB_XX}
    )

    target_compile_features( "${LIB_NAME}" PUBLIC cxx_std_26 )
endfunction()

target_compile_features( dot-xx-assert   PRIVATE cxx_std_26 )
target_compile_features( dot-xx-cstd     PRIVATE cxx_std_26 )
target_compile_features( dot-xx-overload PRIVATE cxx_std_26 )
target_compile_features( dot-xx-selftest PRIVATE cxx_std_26 )

add_module_library( cadjit )
target_link_libraries( cadjit PRIVATE capstone dot-xx::all reflectcpp )

add_module_library( provider_interface )

add_library( provider1 SHARED src/provider1/provider.cc )
target_compile_features( provider1 PRIVATE cxx_std_26 )
target_link_libraries( provider1 PUBLIC provider_interface )

add_library( provider2 SHARED src/provider2/provider.cc )
target_compile_features( provider2 PRIVATE cxx_std_26 )
target_link_libraries( provider2 PUBLIC provider_interface )

add_executable( selftest test/main.cc )
target_compile_features( selftest PRIVATE cxx_std_26 )
target_link_libraries( selftest PRIVATE cadjit dot-xx::all provider1 )
