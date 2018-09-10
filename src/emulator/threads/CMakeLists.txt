add_library(
	threads
	INTERFACE
)

target_include_directories(threads INTERFACE include)
target_link_libraries(threads INTERFACE ${Boost_LIBRARIES})
