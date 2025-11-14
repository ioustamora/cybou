# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Debug")
  file(REMOVE_RECURSE
  "CMakeFiles/qpostquantumwallet_autogen.dir/AutogenUsed.txt"
  "CMakeFiles/qpostquantumwallet_autogen.dir/ParseCache.txt"
  "qpostquantumwallet_autogen"
  )
endif()
