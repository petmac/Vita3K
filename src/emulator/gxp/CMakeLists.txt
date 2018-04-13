add_library(
	gxp
	STATIC
	include/gxp/functions.h
	include/gxp/types.h
	src/gxp.cpp
)

target_include_directories(gxp PUBLIC include)
target_link_libraries(gxp PUBLIC rpcs3)
