#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <trousers/tss.h>
#include "common.h"

void *thread_main_nosync( void *ptr );
void *thread_main_sync_big( void *ptr );
void *thread_main_sync_fine( void *ptr );
void getAttribData();
void pcrRead();
void pcrExtend();
void getEventLog();
void createKey();


/*
 * - set to 1 for single-threaded execution
 * - set ot 2 or bigger for multiple concurrent threads
 */
#define NUM_THREADS 99

/*
 * if EXIT_ON_ERROR is defined, the program exits as soon as an error code other than TSS_SUCCESS
 * is received
 */
//#undef EXIT_ON_ERROR
#define EXIT_ON_ERROR

#ifdef EXIT_ON_ERROR
#define EXIT(x)		exit(x)
#else
#define EXIT(x)
#endif

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;

main()
{
	pthread_t threads[NUM_THREADS];
	int i;

	/*
	 *  choose different thread main loops here:
	 *  - thread_main_nosync: no synchronization done for accessing the TSS
	 *
	 *  - thread_main_sync_big: synchronization done per thread
	 *
	 *  - thread_main_sync_fine: synchronization done per function
	 */
	void *func = thread_main_nosync;
	//  void *func = thread_main_sync_big;
	//  void *func = thread_main_sync_fine;

	for (i = 0; i < NUM_THREADS; i++) {
		pthread_create(&threads[i], NULL, func, NULL);
	}

	for (i = 0; i < NUM_THREADS; i++) {
		pthread_join( threads[i], NULL);
	}

	exit(0);
}


/*
  do not synchronize TSS access
  (assumption: TSS (or more precicely TSP) is thread safe)
*/
void *thread_main_nosync( void *ptr )
{
	createKey();
	getAttribData();
	pcrExtend();
	getEventLog();
}


/*
  synchronize TSS access per thread
*/
void *thread_main_sync_big( void *ptr )
{
	pthread_mutex_lock(&mutex);
	createKey();
	getAttribData();
	pcrExtend();
	getEventLog();
	pthread_mutex_unlock(&mutex);
}


/*
  synchronize TSS access per function
*/
void *thread_main_sync_fine( void *ptr )
{
	pthread_mutex_lock(&mutex);
	createKey();
	pthread_mutex_unlock(&mutex);

	pthread_mutex_lock(&mutex);
	getAttribData();
	pthread_mutex_unlock(&mutex);

	pthread_mutex_lock(&mutex);
	pcrExtend();
	pthread_mutex_unlock(&mutex);

	pthread_mutex_lock(&mutex);
	getEventLog();
	pthread_mutex_unlock(&mutex);
}




// ------------------------------------------------------------------------------------------------
// below these line are functions taken from the testsuite
// note: the SRK secret is hard-coded to TSS_SECRET_MODE_NONE (used in one single place only).

void getAttribData()
{
	char    *nameOfFunction = "Tspi_GetAttribData01";
	TSS_HCONTEXT  hContext;
	TSS_RESULT  result;
	TSS_HKEY  hSRK;
	BYTE*   BLOB;
	UINT32    BlobLength;

	print_begin_test(nameOfFunction);

	//Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		print_error_exit(nameOfFunction, err_string(result));
		EXIT(result);
	}
	//Connect Context
	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		EXIT(result);
	}
	//Load Key by UUID for SRK
	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		EXIT(result);
	}
	//Call GetAttribData
	result = Tspi_GetAttribData(hSRK, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB,
				    &BlobLength, &BLOB);
	if (result != TSS_SUCCESS) {
		if (!checkNonAPI(result)){
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_Close(hContext);
			exit(result);
		} else {
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_FreeMemory(hContext, NULL);
			Tspi_Context_Close(hContext);
			EXIT(result);
		}
	} else {
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_FreeMemory(hContext, NULL);
		Tspi_Context_Close(hContext);
	}
}


void pcrExtend()
{

	char    *nameOfFunction = "Tspi_TPM_PcrExtend01";
	TSS_HCONTEXT  hContext;
	TSS_HTPM  hTPM;
	BYTE    pcrValue;
	UINT32    ulNewPcrValueLength;
	BYTE*    NewPcrValue;
	TSS_RESULT  result;

	TSS_PCR_EVENT event;
	memset(&event, 0, sizeof(TSS_PCR_EVENT));
	event.ulPcrIndex = 9;

	print_begin_test(nameOfFunction);


	//Create Context
	result  = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		EXIT(result);
	}
	//Connect Context
	result  = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect", result);
		EXIT(result);
	}
	//Get TPM Object
	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetTpmObject", result);
		EXIT(result);
	}
	//Call PcrExtend
	result = Tspi_TPM_PcrExtend(hTPM, 9, 20, &pcrValue, &event, &ulNewPcrValueLength,
				    &NewPcrValue);
	if (result != TSS_SUCCESS) {
		if(!checkNonAPI(result)){
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			EXIT(result);
		} else {
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			EXIT(result);
		}
	} else {
		result = Tspi_Context_FreeMemory(hContext, NewPcrValue);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_Context_FreeMemory ", result);
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_Close(hContext);
			EXIT(result);
		}
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
	}
}

void
getEventLog()
{
	char    *nameOfFunction = "Tspi_TPM_GetEventLog01";
	TSS_HCONTEXT  hContext;
	TSS_RESULT  result;
	TSS_HTPM  hTPM;
	UINT32    ulEventNumber;
	TSS_PCR_EVENT*  PCREvents;

	print_begin_test(nameOfFunction);

	//Create Result
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		print_error_exit(nameOfFunction, err_string(result));
		EXIT(result);
	}
	//Connect Result
	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		EXIT(result);
	}
	//Get TPM Object
	result = Tspi_Context_GetTpmObject(hContext,  &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetTpmObject ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		EXIT(result);
	}
	//Get Event
	result = Tspi_TPM_GetEventLog(hTPM, &ulEventNumber, &PCREvents);
	if (result != TSS_SUCCESS) {
		if (!checkNonAPI(result)){
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			EXIT(result);
		} else {
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_Close(hContext);
			EXIT(result);
		}
	} else {
		result = Tspi_Context_FreeMemory(hContext, (BYTE *)PCREvents);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_Context_FreeMemory ", result);
			print_error_exit(nameOfFunction, err_string(result));
			Tspi_Context_Close(hContext);
			EXIT(result);
		}
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_Close(hContext);
	}
}



void createKey()
{
	char    *nameOfFunction = "Tspi_Key_CreateKey01";
	TSS_HCONTEXT  hContext;
	TSS_HTPM  hTPM;
	TSS_FLAG  initFlags;
	TSS_HKEY  hKey;
	TSS_HKEY  hSRK;
	TSS_RESULT  result;
	TSS_UUID  uuid;
	BYTE    *randomData;
	TSS_HPOLICY srkUsagePolicy, keyUsagePolicy, keyMigPolicy;


	initFlags = TSS_KEY_TYPE_SIGNING | TSS_KEY_SIZE_512  |
		TSS_KEY_VOLATILE | TSS_KEY_AUTHORIZATION |
		TSS_KEY_NOT_MIGRATABLE;

	print_begin_test(nameOfFunction);

	//Create Context
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create", result);
		print_error_exit(nameOfFunction, err_string(result));
		EXIT(result);
	}
	//Connect Context
	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		EXIT(result);
	}

	//Create Object
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, &hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		EXIT(result);

	}
	//Load Key By UUID
	result = Tspi_Context_LoadKeyByUUID(hContext,
			TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		EXIT(result);
	}

	//Get Policy Object
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		EXIT(result);
	}
	//Set Secret
	result = Tspi_Policy_SetSecret(srkUsagePolicy, TESTSUITE_SRK_SECRET_MODE,
				       TESTSUITE_SRK_SECRET_LEN, TESTSUITE_SRK_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		EXIT(result);
	}

	//Get Policy Object
	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_POLICY, TSS_POLICY_USAGE,
					   &keyUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		EXIT(result);
	}
	//Set Secret
	result = Tspi_Policy_SetSecret(keyUsagePolicy, TSS_SECRET_MODE_PLAIN, 0, NULL);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		EXIT(result);
	}

	result = Tspi_Policy_AssignToObject(keyUsagePolicy, hKey);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_AssignToObject", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		EXIT(result);
	}

	//Create Key
	result = Tspi_Key_CreateKey(hKey, hSRK, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
		EXIT(result);
	}

	result = Tspi_Key_LoadKey(hKey, hSRK);
	if (result != TSS_SUCCESS){
		if (!checkNonAPI(result)){
			print_error(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_Close(hContext);
			EXIT(result);
		} else {
			print_error_nonapi(nameOfFunction, result);
			print_end_test(nameOfFunction);
			Tspi_Context_CloseObject(hContext, hKey);
			Tspi_Context_Close(hContext);
			EXIT(result);
		}
	} else {
		print_success(nameOfFunction, result);
		print_end_test(nameOfFunction);
		Tspi_Context_CloseObject(hContext, hKey);
		Tspi_Context_Close(hContext);
	}
}

