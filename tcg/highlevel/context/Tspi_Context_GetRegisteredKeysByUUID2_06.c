/*
 *
 *   Copyright (C) International Business Machines  Corp., 2004-2007
 *
 *   This program is free software;  you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY;  without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *   the GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program;  if not, write to the Free Software
 *   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

/*
 * NAME
 *	Tspi_Context_GetRegisteredKeysByUUID2_06.c
 *
 * DESCRIPTION
 *	This test will verify Tspi_Context_GetRegisteredKeysByUUID2 returns the
 *	correct key hierarchy given several different scenarios.
 *
 *	First, set up a key hierarchy that has several branches, each with a set
 *	number of children.  Then, call Tspi_Context_GetRegisteredKeysByUUID2
 *	on each node and make sure the correct set of key info structs is returned.
 *
 *
 * ALGORITHM
 *	Setup:
 *		Create
 *		Connect
 *		Get TPM Object
 *		Create Object
 *		Load Key by UUID
 *		SetAttribUint32
 *		SetAttribUint32
 *
 *	Test:	Call GetRegisteredKeyByUUID2. If it is not a success
 *		Call the Common Errors 
 *		Make sure that it returns the proper return codes
 *
 *	Cleanup:
 *		Free memory associated with the context
 *		Close the context
 *		Print error/success message
 *
 * USAGE:	First parameter is --options
 *			-v or --version
 *		Second Parameter is the version of the test case to be run.
 *		This test case is currently only implemented for 1.1 and 1.2
 *
 *
 * HISTORY
 *	Author:	Kent Yoder <kyoder@users.sf.net>, 12/06
 *  Adapted for TSS 1.2 and TSS_KM_KEYINFO2 compatibility: Ramon Brandao
 *  <ramongb@br.ibm.com>, 07/11
 *
 * RESTRICTIONS
 *	None.
 */

#include <stdlib.h>

#include "common.h"


TSS_HCONTEXT hContext;
char *nameOfFunction = "Tspi_Context_GetRegisteredKeysByUUID2_06";
TSS_UUID NULL_UUID = { 0, 0, 0, 0, 0, { 0, 0, 0, 0, 0, 0 } };

/* The number of child keys per storage key */
#define NUM_CHILDREN   3

struct node
{
	TSS_UUID uuid;
	TSS_HKEY handle;
	UINT32 ps_type;
	struct node *parent;
	struct node *children[NUM_CHILDREN+1];
};

int main(int argc, char **argv)
{
	char version;

	version = parseArgs(argc, argv);
	if (version ==  TESTSUITE_TEST_TSS_1_2)
		main_v1_2(version);
	else if (version == TESTSUITE_TEST_TSS_1_1)
		print_NA();
	else
		print_wrongVersion();
}

TSS_RESULT
create_child_keys(TSS_HKEY hParentKey, struct node *parentNode)
{
	TSS_RESULT result;
	UINT32 i;
	TSS_FLAG signInitFlags = TSS_KEY_TYPE_SIGNING | TSS_KEY_NO_AUTHORIZATION;

	parentNode->children[0] = calloc(NUM_CHILDREN, sizeof(struct node));

	if (!parentNode->children[0])
		return TSS_E_OUTOFMEMORY;

	for (i = 0; i < NUM_CHILDREN-1; i++) {
		/* 1 is sizeof(struct node), the next contiguous block returned from calloc */
		parentNode->children[i+1] = parentNode->children[i] + 1;
	}

	for (i = 0; i < NUM_CHILDREN; i++)
		parentNode->children[i]->parent = parentNode;

	for (i = 0; i < NUM_CHILDREN; i++)
		memcpy(&parentNode->children[i]->uuid, &parentNode->uuid, sizeof(TSS_UUID));

	/* Give each child a unique version of the parent's UUID */
	for (i = 0; i < NUM_CHILDREN; i++)
		parentNode->children[i]->uuid.usTimeMid += i+1;

		//Create 512 bit key Object
	for (i = 0; i < NUM_CHILDREN; i++) {
		result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY, signInitFlags,
						   &parentNode->children[i]->handle);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_Context_CreateObject ", result);
			print_error_exit(nameOfFunction, err_string(result));
			return result;
		}
		result = Tspi_Key_CreateKey(parentNode->children[i]->handle, hParentKey, 0);
		if (result != TSS_SUCCESS) {
			print_error("Tspi_Key_CreateKey", result);
			print_error_exit(nameOfFunction, err_string(result));
			return result;
		}
	}

	return TSS_SUCCESS;
}

void
unregister_node(struct node *n)
{
	TSS_HKEY trash;
	UINT32 i;

	if (!n)
		return;

	if (memcmp(&SRK_UUID, &n->uuid, sizeof(TSS_UUID))) {
		Tspi_Context_UnregisterKey(hContext, TSS_PS_TYPE_SYSTEM, n->uuid, &trash);
		Tspi_Context_UnregisterKey(hContext, TSS_PS_TYPE_USER, n->uuid, &trash);
		n->ps_type = 0;
	}

	for (i = 0; i < NUM_CHILDREN+1; i++)
		unregister_node(n->children[i]);
}

TSS_RESULT
register_node(struct node *n, UINT32 ps_type)
{
	TSS_RESULT result;
	TSS_HKEY trash;
	UINT32 i, parent_ps;
	TSS_UUID *parent_uuid;

	if (!n)
		return TSS_SUCCESS;

	parent_uuid = n->parent ? &n->parent->uuid : &NULL_UUID;
	parent_ps = n->parent ? n->parent->ps_type : TSS_PS_TYPE_SYSTEM;

	if (memcmp(&SRK_UUID, &n->uuid, sizeof(TSS_UUID))) {
		if ((result = Tspi_Context_RegisterKey(hContext, n->handle, ps_type, n->uuid,
						       parent_ps, *parent_uuid))) {
			print_error("Tspi_Context_RegisterKey ", result);
			print_error_exit(nameOfFunction, err_string(result));
			return result;
		}

		n->ps_type = ps_type;
	}

	for (i = 0; i < NUM_CHILDREN+1; i++) {
		if ((result = register_node(n->children[i], ps_type)))
			return result;
	}

	return TSS_SUCCESS;
}

int
verify_hierarchy2(struct node *n, TSS_KM_KEYINFO2 *ppKeyHierarchy, UINT32 size)
{
	UINT32 i, keys_found = 0;
	struct node *node_ptr;

	/* If the parent of n is NULL, we're at the top of the node structure, so do a top-down
	 * tree verify. Otherwise, we're somewhere inside a tree, so verify from this node up
	 * to the top of the tree
	 */

	if (!n->parent) {
		return 1;
	}

	/* Verify up the tree */
	node_ptr = n;

	while (node_ptr->parent) {
		for (i = 0; i < size; i++) {
			if (!memcmp(&node_ptr->uuid, &ppKeyHierarchy[i].keyUUID,
				    sizeof(TSS_UUID)) &&
			    !memcmp(&node_ptr->parent->uuid, &ppKeyHierarchy[i].parentKeyUUID,
				    sizeof(TSS_UUID))) {
				node_ptr = node_ptr->parent;
				keys_found++;
				break;
			}
		}

		if (i == size) {
			fprintf(stderr, "UUID match not found\n");
			return 1;
		}
	}

	/* Everything in the tree verified, now verify the root node */
	for (i = 0; i < size; i++) {
		if (!memcmp(&node_ptr->uuid, &ppKeyHierarchy[i].keyUUID, sizeof(TSS_UUID))) {
			keys_found++;
			break;
		}
	}

	if (i == size) {
		fprintf(stderr, "UUID match not found\n");
		return 1;
	}

	/* If we've found each key in the tree up to the top and the key hierarchy has exactly
	 * that number of keys in it, keys_found should equal size and therefore we'll
	 * return 0 here. Otherwise, its a fail.
	 */
	return (keys_found - size);
}

int
main_v1_2(char version){
	
	TSS_HTPM	hTPM;
	TSS_FLAG	storeInitFlags;
	TSS_HKEY	hSRK;
	TSS_RESULT	result;
	TSS_HPOLICY	srkUsagePolicy;
	int i;
	UINT32		pulKeyHierarchySize;
	TSS_KM_KEYINFO2*	ppKeyHierarchy;
	struct node	storage[3];

	storeInitFlags	= TSS_KEY_SIZE_2048 | TSS_KEY_TYPE_STORAGE | TSS_KEY_NO_AUTHORIZATION;

	memset(&storage, 0, sizeof(struct node) * 3);

	print_begin_test(nameOfFunction);

		//Create
	result = Tspi_Context_Create(&hContext);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Create ", result);
		print_error_exit(nameOfFunction, err_string(result));
		exit(result);
	}
		//Connect
	result = Tspi_Context_Connect(hContext, get_server(GLOBALSERVER));
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_Connect ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Get TPM Object
	result = Tspi_Context_GetTpmObject(hContext, &hTPM);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetTpmObject ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Load Key by UUID
	result = Tspi_Context_LoadKeyByUUID(hContext, TSS_PS_TYPE_SYSTEM,
						SRK_UUID, &hSRK);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_LoadKeyByUUID ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
#ifndef TESTSUITE_NOAUTH_SRK
		//Get Policy Object for the srkUsagePolicy
	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &srkUsagePolicy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_GetPolicyObject ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
		//Set Secret for the srkUsagePolicy
	result = Tspi_Policy_SetSecret(srkUsagePolicy, TESTSUITE_SRK_SECRET_MODE,
			TESTSUITE_SRK_SECRET_LEN, TESTSUITE_SRK_SECRET);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Policy_SetSecret ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
#endif

	storage[0].handle = hSRK;
	storage[0].ps_type = TSS_PS_TYPE_SYSTEM;
	memcpy(&storage[0].uuid, &SRK_UUID, sizeof(TSS_UUID));
	memcpy(&storage[1].uuid, &SRK_UUID, sizeof(TSS_UUID));
	storage[1].uuid.ulTimeLow += 1;
	storage[1].parent = &storage[0];
	memcpy(&storage[2].uuid, &SRK_UUID, sizeof(TSS_UUID));
	storage[2].uuid.ulTimeLow += 2;
	storage[2].parent = &storage[1];

	if ((result = create_child_keys(hSRK, &storage[0])))
		return result;

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
					   storeInitFlags, &storage[1].handle);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_Key_CreateKey(storage[1].handle, storage[0].handle, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Key_LoadKey(storage[1].handle, storage[0].handle);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_LoadKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	if ((result = create_child_keys(storage[1].handle, &storage[1])))
		return result;

	result = Tspi_Context_CreateObject(hContext, TSS_OBJECT_TYPE_RSAKEY,
					   storeInitFlags, &storage[2].handle);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_CreateObject ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}
	result = Tspi_Key_CreateKey(storage[2].handle, storage[1].handle, 0);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_CreateKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	result = Tspi_Key_LoadKey(storage[2].handle, storage[1].handle);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Key_LoadKey", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	if ((result = create_child_keys(storage[2].handle, &storage[2])))
		return result;

	storage[0].children[NUM_CHILDREN] = &storage[1];
	storage[1].children[NUM_CHILDREN] = &storage[2];

	/* We now have a key hierarchy (not yet reg'd), that has 3 child signing keys
	 * for the SRK, 3 for a child of the SRK and 3 for a grandchild of the SRK */
	printf("***** SYSTEM PS TESTING...\n");

	/* unregister all keys in the node structure to prep for the test */
	unregister_node(&storage[0]);

	/*********  TEST 1 ****************/
	/* Call Tspi_Context_GetRegisteredKeysByUUID2 on a non-existant UUID */

	result = Tspi_Context_GetRegisteredKeysByUUID2(hContext, TSS_PS_TYPE_SYSTEM,
						      &storage[2].uuid, &pulKeyHierarchySize,
						      &ppKeyHierarchy);
	if (TSS_ERROR_CODE(result) != TSS_E_PS_KEY_NOTFOUND) {
		print_error("Tspi_Context_GetRegisteredKeysByUUID ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	/*********  TEST 2 ****************/
	/* Register all keys, then call Tspi_Context_GetRegisteredKeysByUUID on the SRK */

	if ((result = register_node(&storage[0], TSS_PS_TYPE_SYSTEM)))
		goto done;

	// Get Registered Keys By UUID
	result = Tspi_Context_GetRegisteredKeysByUUID2(hContext, TSS_PS_TYPE_SYSTEM, &SRK_UUID,
						      &pulKeyHierarchySize, &ppKeyHierarchy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetRegisteredKeysByUUID ", result);
		print_error_exit(nameOfFunction, err_string(result));
		goto done;
	}

	if (pulKeyHierarchySize != 1) {
		print_verifyerr("key hierarchy size", 1, pulKeyHierarchySize);
		print_error_exit(nameOfFunction, err_string(result));
		goto done;
	}

	if (memcmp(&ppKeyHierarchy->keyUUID, &SRK_UUID, sizeof(TSS_UUID)) ||
	    memcmp(&ppKeyHierarchy->parentKeyUUID, &NULL_UUID, sizeof(TSS_UUID))) {
		print_verifystr("key hierarchy UUIDs", "NULL_UUID->SRK_UUID",
				"something else");
		print_error_exit(nameOfFunction, err_string(result));
		goto done;
	}

	/*********  TEST 3 ****************/
	/* Call Tspi_Context_GetRegisteredKeysByUUID2 on a leaf key of the SRK */
	result = Tspi_Context_GetRegisteredKeysByUUID2(hContext, TSS_PS_TYPE_SYSTEM,
						      &storage[0].children[0]->uuid,
						      &pulKeyHierarchySize, &ppKeyHierarchy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetRegisteredKeysByUUID ", result);
		print_error_exit(nameOfFunction, err_string(result));
		goto done;
	}

	if (verify_hierarchy2(storage[0].children[0], ppKeyHierarchy, pulKeyHierarchySize)) {
		print_verifystr("key hierarchy", "valid hierarchy", "bad hierarchy");
		print_error_exit(nameOfFunction, err_string(result));
		if ((result = Tspi_Context_FreeMemory(hContext, (BYTE *)ppKeyHierarchy))) {
			print_error("Tspi_Context_FreeMemory ", result);
			print_error_exit(nameOfFunction, err_string(result));
		}
		goto done;
	}
	if ((result = Tspi_Context_FreeMemory(hContext, (BYTE *)ppKeyHierarchy))) {
		print_error("Tspi_Context_FreeMemory ", result);
		print_error_exit(nameOfFunction, err_string(result));
	}

	/*********  TEST 4 ****************/
	/* Call Tspi_Context_GetRegisteredKeysByUUID2 on a leaf key of a child of the SRK */
	result = Tspi_Context_GetRegisteredKeysByUUID2(hContext, TSS_PS_TYPE_SYSTEM,
						      &storage[1].children[0]->uuid,
						      &pulKeyHierarchySize, &ppKeyHierarchy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetRegisteredKeysByUUID ", result);
		print_error_exit(nameOfFunction, err_string(result));
		goto done;
	}

	if (verify_hierarchy2(storage[1].children[0], ppKeyHierarchy, pulKeyHierarchySize)) {
		print_verifystr("key hierarchy", "valid hierarchy", "bad hierarchy");
		print_error_exit(nameOfFunction, err_string(result));
		if ((result = Tspi_Context_FreeMemory(hContext, (BYTE *)ppKeyHierarchy))) {
			print_error("Tspi_Context_FreeMemory ", result);
			print_error_exit(nameOfFunction, err_string(result));
		}
		goto done;
	}
	if ((result = Tspi_Context_FreeMemory(hContext, (BYTE *)ppKeyHierarchy))) {
		print_error("Tspi_Context_FreeMemory ", result);
		print_error_exit(nameOfFunction, err_string(result));
	}

	/*********  TEST 5 ****************/
	/* Call Tspi_Context_GetRegisteredKeysByUUID2 on a leaf key of a child of the SRK */
	result = Tspi_Context_GetRegisteredKeysByUUID2(hContext, TSS_PS_TYPE_SYSTEM,
						      &storage[2].children[0]->uuid,
						      &pulKeyHierarchySize, &ppKeyHierarchy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetRegisteredKeysByUUID ", result);
		print_error_exit(nameOfFunction, err_string(result));
		goto done;
	}

	if (verify_hierarchy2(storage[2].children[0], ppKeyHierarchy, pulKeyHierarchySize)) {
		print_verifystr("key hierarchy", "valid hierarchy", "bad hierarchy");
		print_error_exit(nameOfFunction, err_string(result));
		if ((result = Tspi_Context_FreeMemory(hContext, (BYTE *)ppKeyHierarchy))) {
			print_error("Tspi_Context_FreeMemory ", result);
			print_error_exit(nameOfFunction, err_string(result));
		}
		goto done;
	}
	if ((result = Tspi_Context_FreeMemory(hContext, (BYTE *)ppKeyHierarchy))) {
		print_error("Tspi_Context_FreeMemory ", result);
		print_error_exit(nameOfFunction, err_string(result));
	}




	/********* USER PS TESTS **********/
	printf("***** USER PS TESTING...\n");

	/* unregister all keys in the node structure to prep for the test */
	unregister_node(&storage[0]);

	/*********  TEST 1 ****************/
	/* Call Tspi_Context_GetRegisteredKeysByUUID on a non-existant UUID */

	result = Tspi_Context_GetRegisteredKeysByUUID2(hContext, TSS_PS_TYPE_USER, &storage[2].uuid,
						      &pulKeyHierarchySize, &ppKeyHierarchy);
	if (TSS_ERROR_CODE(result) != TSS_E_PS_KEY_NOTFOUND) {
		print_error("Tspi_Context_GetRegisteredKeysByUUID ", result);
		print_error_exit(nameOfFunction, err_string(result));
		Tspi_Context_Close(hContext);
		exit(result);
	}

	if ((result = register_node(&storage[0], TSS_PS_TYPE_USER)))
		goto done;

	/*********  TEST 2 ****************/
	/* Call Tspi_Context_GetRegisteredKeysByUUID2 on a leaf key of the SRK */
	result = Tspi_Context_GetRegisteredKeysByUUID2(hContext, TSS_PS_TYPE_USER,
						      &storage[0].children[0]->uuid,
						      &pulKeyHierarchySize, &ppKeyHierarchy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetRegisteredKeysByUUID ", result);
		print_error_exit(nameOfFunction, err_string(result));
		goto done;
	}

	if (verify_hierarchy2(storage[0].children[0], ppKeyHierarchy, pulKeyHierarchySize)) {
		print_verifystr("key hierarchy", "valid hierarchy", "bad hierarchy");
		print_error_exit(nameOfFunction, err_string(result));
		if ((result = Tspi_Context_FreeMemory(hContext, (BYTE *)ppKeyHierarchy))) {
			print_error("Tspi_Context_FreeMemory ", result);
			print_error_exit(nameOfFunction, err_string(result));
		}
		goto done;
	}

	if ((result = Tspi_Context_FreeMemory(hContext, (BYTE *)ppKeyHierarchy))) {
		print_error("Tspi_Context_FreeMemory ", result);
		print_error_exit(nameOfFunction, err_string(result));
	}

	/*********  TEST 3 ****************/
	/* Call Tspi_Context_GetRegisteredKeysByUUID2 on a leaf key of the SRK's child */
	result = Tspi_Context_GetRegisteredKeysByUUID2(hContext, TSS_PS_TYPE_USER,
						      &storage[1].children[0]->uuid,
						      &pulKeyHierarchySize, &ppKeyHierarchy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetRegisteredKeysByUUID ", result);
		print_error_exit(nameOfFunction, err_string(result));
		goto done;
	}

	if (verify_hierarchy2(storage[1].children[0], ppKeyHierarchy, pulKeyHierarchySize)) {
		print_verifystr("key hierarchy", "valid hierarchy", "bad hierarchy");
		print_error_exit(nameOfFunction, err_string(result));
		if ((result = Tspi_Context_FreeMemory(hContext, (BYTE *)ppKeyHierarchy))) {
			print_error("Tspi_Context_FreeMemory ", result);
			print_error_exit(nameOfFunction, err_string(result));
		}
		goto done;
	}

	if ((result = Tspi_Context_FreeMemory(hContext, (BYTE *)ppKeyHierarchy))) {
		print_error("Tspi_Context_FreeMemory ", result);
		print_error_exit(nameOfFunction, err_string(result));
	}

	/*********  TEST 4 ****************/
	/* Call Tspi_Context_GetRegisteredKeysByUUID2 on a leaf key of the SRK's grandchild */
	result = Tspi_Context_GetRegisteredKeysByUUID2(hContext, TSS_PS_TYPE_USER,
						      &storage[2].children[0]->uuid,
						      &pulKeyHierarchySize, &ppKeyHierarchy);
	if (result != TSS_SUCCESS) {
		print_error("Tspi_Context_GetRegisteredKeysByUUID ", result);
		print_error_exit(nameOfFunction, err_string(result));
		goto done;
	}

	if (verify_hierarchy2(storage[2].children[0], ppKeyHierarchy, pulKeyHierarchySize)) {
		print_verifystr("key hierarchy", "valid hierarchy", "bad hierarchy");
		print_error_exit(nameOfFunction, err_string(result));
		if ((result = Tspi_Context_FreeMemory(hContext, (BYTE *)ppKeyHierarchy))) {
			print_error("Tspi_Context_FreeMemory ", result);
			print_error_exit(nameOfFunction, err_string(result));
		}
		goto done;
	}

	if ((result = Tspi_Context_FreeMemory(hContext, (BYTE *)ppKeyHierarchy))) {
		print_error("Tspi_Context_FreeMemory ", result);
		print_error_exit(nameOfFunction, err_string(result));
	}

	print_success( nameOfFunction, result );
	print_end_test( nameOfFunction );

done:
	unregister_node(&storage[0]);
	Tspi_Context_Close(hContext);

	exit(result);
}
