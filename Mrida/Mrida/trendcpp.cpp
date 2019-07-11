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

void trendcpp::add_threat_to_database(unsigned long int id, std::string tlsh_hash, std::string threat_name, unsigned long file_size, unsigned int file_type, unsigned int target_os)
{
	try {
		sqlite::database threat_database("threat_db.sqlite3");
		threat_database << "create table if not exists threat(id unsigned bigint primary key, threat_hash text, threat_name text, threat_size unsigned int, threat_type unsigned int, target_os unsigned tinyint);";
		threat_database << "insert into threat(id, threat_hash, threat_name, threat_size, threat_type, target_os) values(?, ?, ?, ?, ?, ?)" << id << tlsh_hash << threat_name << file_size << file_type << target_os;
		threat_database << "SELECT * FROM threat WHERE editdist3(threat_hash, \"a\") < 600";
	}
	catch (std::exception &e)
	{
		std::cout << e.what();
	}
}
