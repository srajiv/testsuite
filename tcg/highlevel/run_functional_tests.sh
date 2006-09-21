#!/bin/sh

#
# The testcases run by this script are hereby deemed "safe" to run on any TSS.
# This means that there are no undesirable side-effects from running them, such
# as clearing the TPM owner. Its noted below when PCR registers are extended.
#

VERSION=

if test "x$1" == "x"; then
	VERSION=1.1
else
	VERSION=$1
fi

if test x`which rngtest` != x; then
	./tpm_rng_test | rngtest
fi

# context tests
./context/Tspi_Context_Connect03 -v $VERSION || exit $?
./context/Tspi_Context_LoadKeyByBlob04 -v $VERSION || exit $?
./context/Tspi_Context_RegisterKey05 -v $VERSION || exit $?
./context/Tspi_Context_LoadKeyByUUID06 -v $VERSION || exit $?
./context/Tspi_Context_Connect04 -v $VERSION || exit $?
./context/Tspi_Context_CreateDataObject01 -v $VERSION || exit $?
./context/Tspi_Context_CreateHashObject01 -v $VERSION || exit $?
./context/Tspi_Context_CreatePcrsObject01 -v $VERSION || exit $?
./context/Tspi_Context_CreatePolicyObject01 -v $VERSION || exit $?

# key tests
./key/Tspi_Key_CreateKey05 -v $VERSION || exit $?
# Warning: These two will trash a PCR!
./key/Tspi_Key_CreateKeyWithPcrs -v $VERSION || exit $?
./key/Tspi_Key_WrapKeyToPcr -v $VERSION || exit $?
./key/Tspi_Key_ConvertMigrationBlob02 -v $VERSION || exit $?

# tpm tests
./tpm/Tspi_TPM_Quote05 -v $VERSION || exit $?
./tpm/Tspi_TPM_PcrRead04 -v $VERSION || exit $?
# Warning: Tspi_TPM_PcrExtend05 will trash all PCRs
./tpm/Tspi_TPM_PcrExtend05 -v $VERSION || exit $?
./tpm/./Tspi_TPM_GetStatus04 -v $VERSION || exit $?
./tpm/./Tspi_TPM_GetEvents06 -v $VERSION || exit $?
./tpm/./Tspi_TPM_GetEvents07 -v $VERSION || exit $?
./tpm/Tspi_TPM_GetEventLog05 -v $VERSION || exit $?
./tpm/Tspi_TPM_GetEventLog06 -v $VERSION || exit $?
./tpm/Tspi_TPM_GetCapability04 -v $VERSION || exit $?
./tpm/Tspi_TPM_GetCapability05 -v $VERSION || exit $?
./tpm/Tspi_TPM_GetCapability06 -v $VERSION || exit $?
./tpm/Tspi_TPM_GetCapability07 -v $VERSION || exit $?
./tpm/Tspi_TPM_DirWrite04 -v $VERSION || exit $?
./tpm/Tspi_TPM_CreateIdentity -v $VERSION || exit $?

# tspi tests
./tspi/Tspi_Callbacks01 -v $VERSION || exit $?
./tspi/Tspi_ChangeAuth05 -v $VERSION || exit $?
./tspi/Tspi_ChangeAuth06 -v $VERSION || exit $?
./tspi/Tspi_ChangeAuth07 -v $VERSION || exit $?
./tspi/Tspi_Context_GetCapability18 -v $VERSION || exit $?
./tspi/Tspi_Context_GetCapability19 -v $VERSION || exit $?

# data tests
./data/Tspi_Data_Unbind05 -v $VERSION || exit $?
./data/Tspi_Data_Unbind06 -v $VERSION || exit $?
./data/Tspi_Data_Unbind07 -v $VERSION || exit $?
./data/Tspi_Data_Unbind08 -v $VERSION || exit $?
./data/Tspi_Data_Unseal05 -v $VERSION || exit $?
./data/Tspi_Data_Unseal06 -v $VERSION || exit $?

# XXX This is an incomplete list...


echo "************************"
echo "$0: ALL TESTS SUCCEEDED "
echo "************************"

exit 0
