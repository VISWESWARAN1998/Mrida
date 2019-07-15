// SWAMI KARUPPASWAMI THUNNAI

#pragma warning(disable: 4996)

#include "trendcpp.h"
#include <experimental/filesystem>
#include <sqlite_modern_cpp.h>



trendcpp::trendcpp()
{
	
}


trendcpp::~trendcpp()
{
}

std::string trendcpp::hash_file_to_string(std::string file_location)
{
	if (!std::experimental::filesystem::exists(file_location)) return "";
	Tlsh th;
	///////////////////////////////////////
	// 1. How big is the file?
	///////////////////////////////////////
	FILE *fd = fopen(file_location.c_str(), "r");
	if (fd == NULL)
		return "";
	int ret = 1;
	int sizefile = 0;

	fseek(fd, 0L, SEEK_END);
	sizefile = ftell(fd);

	fclose(fd);

	if (sizefile < MIN_DATA_LENGTH)
		return "";

	///////////////////////////////////////
	// 2. allocate the memory
	///////////////////////////////////////
	unsigned char* data = (unsigned char*)malloc(sizefile);
	if (data == NULL) {
		fprintf(stderr, "out of memory...\n");
		exit(0);
	}

	///////////////////////////////////////
	// 3. read the file
	///////////////////////////////////////
#ifdef WINDOWS
	// Handle differently for Windows because the fread function in msvcr80.dll has a bug
	// and it does not always read the entire file.
	if (!read_file_win(file_location.c_str(), sizefile, data)) {
		free(data);
		return "";
	}
#else
	fd = fopen(fname, "r");
	if (fd == NULL) {
		free(data);
		return(ERROR_READING_FILE);
	}

	ret = fread(data, sizeof(unsigned char), sizefile, fd);
	fclose(fd);

	if (ret != sizefile) {
		fprintf(stderr, "fread %d bytes from %s failed: only %d bytes read\n", sizefile, fname, ret);
		return(ERROR_READING_FILE);
	}
#endif

	///////////////////////////////////////
	// 4. calculate the digest
	///////////////////////////////////////
	th.final(data, sizefile, 0);

	///////////////////////////////////////
	// 5. clean up and return
	///////////////////////////////////////
	free(data);
	if (th.getHash() == NULL || th.getHash()[0] == '\0') {
		return "";
	}
	return th.getHash();
}

const Tlsh * trendcpp::hash_file(std::string file_location)
{
	if (!std::experimental::filesystem::exists(file_location)) return nullptr;
	Tlsh th;
	///////////////////////////////////////
	// 1. How big is the file?
	///////////////////////////////////////
	FILE *fd = fopen(file_location.c_str(), "r");
	if (fd == NULL)
		return nullptr;
	int ret = 1;
	int sizefile = 0;

	fseek(fd, 0L, SEEK_END);
	sizefile = ftell(fd);

	fclose(fd);

	if (sizefile < MIN_DATA_LENGTH)
		return nullptr;

	///////////////////////////////////////
	// 2. allocate the memory
	///////////////////////////////////////
	unsigned char* data = (unsigned char*)malloc(sizefile);
	if (data == NULL) {
		fprintf(stderr, "out of memory...\n");
		exit(0);
	}

	///////////////////////////////////////
	// 3. read the file
	///////////////////////////////////////
#ifdef WINDOWS
	// Handle differently for Windows because the fread function in msvcr80.dll has a bug
	// and it does not always read the entire file.
	if (!read_file_win(file_location.c_str(), sizefile, data)) {
		free(data);
		return nullptr;
	}
#else
	fd = fopen(fname, "r");
	if (fd == NULL) {
		free(data);
		return(ERROR_READING_FILE);
	}

	ret = fread(data, sizeof(unsigned char), sizefile, fd);
	fclose(fd);

	if (ret != sizefile) {
		fprintf(stderr, "fread %d bytes from %s failed: only %d bytes read\n", sizefile, fname, ret);
		return(ERROR_READING_FILE);
	}
#endif

	///////////////////////////////////////
	// 4. calculate the digest
	///////////////////////////////////////
	th.final(data, sizefile, 0);

	///////////////////////////////////////
	// 5. clean up and return
	///////////////////////////////////////
	free(data);
	if (th.getHash() == NULL || th.getHash()[0] == '\0') {
		return nullptr;
	}
	return &th;
}

int trendcpp::similarity_distance(std::string hash_one, std::string hash_two)
{
	Tlsh t1;
	Tlsh t2;
	int err1;
	int err2;
	err1 = t1.fromTlshStr(hash_one.c_str());
	err2 = t2.fromTlshStr(hash_two.c_str());
	if (err1 || err2) return -1;
	return t1.totalDiff(&t2);
}

