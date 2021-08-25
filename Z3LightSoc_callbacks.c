/***************************************************************************//**
 * @file
 * @brief
 *******************************************************************************
 * # License
 * <b>Copyright 2018 Silicon Laboratories Inc. www.silabs.com</b>
 *******************************************************************************
 *
 * The licensor of this software is Silicon Laboratories Inc. Your use of this
 * software is governed by the terms of Silicon Labs Master Software License
 * Agreement (MSLA) available at
 * www.silabs.com/about-us/legal/master-software-license-agreement. This
 * software is distributed to you in Source Code format and is governed by the
 * sections of the MSLA applicable to Source Code.
 *
 ******************************************************************************/

// This callback file is created for your convenience. You may add application
// code to this file. If you regenerate this file over a previous version, the
// previous version will be overwritten and any code you have added will be
// lost.

#include "app/framework/include/af.h"
#include MBEDTLS_CONFIG_FILE
#include "mbedtls\sha256.h"
#include "mbedtls\ecdsa.h"
#include "mbedtls\ecp.h"
#include "mbedtls\ctr_drbg.h"

#include EMBER_AF_API_NETWORK_CREATOR
#include EMBER_AF_API_NETWORK_CREATOR_SECURITY
#include EMBER_AF_API_NETWORK_STEERING
#include EMBER_AF_API_FIND_AND_BIND_TARGET
#include EMBER_AF_API_ZLL_PROFILE

#define LIGHT_ENDPOINT (1)

#define MBEDTLS_CTR_DRBG_C

EmberEventControl commissioningLedEventControl;
EmberEventControl findingAndBindingEventControl;

void commissioningLedEventHandler(void)
{
  emberEventControlSetInactive(commissioningLedEventControl);

  if (emberAfNetworkState() == EMBER_JOINED_NETWORK) {
    uint16_t identifyTime;
    emberAfReadServerAttribute(LIGHT_ENDPOINT,
                               ZCL_IDENTIFY_CLUSTER_ID,
                               ZCL_IDENTIFY_TIME_ATTRIBUTE_ID,
                               (uint8_t *)&identifyTime,
                               sizeof(identifyTime));
    if (identifyTime > 0) {
      halToggleLed(COMMISSIONING_STATUS_LED);
      emberEventControlSetDelayMS(commissioningLedEventControl,
                                  LED_BLINK_PERIOD_MS << 1);
    } else {
      halSetLed(COMMISSIONING_STATUS_LED);
    }
  } else {
    EmberStatus status = emberAfPluginNetworkSteeringStart();
    emberAfCorePrintln("%p network %p: 0x%X", "Join", "start", status);
  }
}

void findingAndBindingEventHandler()
{
  if (emberAfNetworkState() == EMBER_JOINED_NETWORK) {
    emberEventControlSetInactive(findingAndBindingEventControl);
    emberAfCorePrintln("Find and bind target start: 0x%X",
                       emberAfPluginFindAndBindTargetStart(LIGHT_ENDPOINT));
  }
}

/** @brief Stack Status
 *
 * This function is called by the application framework from the stack status
 * handler.  This callbacks provides applications an opportunity to be notified
 * of changes to the stack status and take appropriate action.  The return code
 * from this callback is ignored by the framework.  The framework will always
 * process the stack status after the callback returns.
 *
 * @param status   Ver.: always
 */
bool emberAfStackStatusCallback(EmberStatus status)
{
  // Note, the ZLL state is automatically updated by the stack and the plugin.
  if (status == EMBER_NETWORK_DOWN) {
    halClearLed(COMMISSIONING_STATUS_LED);
  } else if (status == EMBER_NETWORK_UP) {
    halSetLed(COMMISSIONING_STATUS_LED);
    emberEventControlSetActive(findingAndBindingEventControl);
  }

// This value is ignored by the framework.
  return false;
}

/** @brief Main Init
 *
 * This function is called from the application's main function. It gives the
 * application a chance to do any initialization required at system startup.
 * Any code that you would normally put into the top of the application's
 * main() routine should be put into this function.
        Note: No callback
 * in the Application Framework is associated with resource cleanup. If you
 * are implementing your application on a Unix host where resource cleanup is
 * a consideration, we expect that you will use the standard Posix system
 * calls, including the use of atexit() and handlers for signals such as
 * SIGTERM, SIGINT, SIGCHLD, SIGPIPE and so on. If you use the signal()
 * function to register your signal handler, please mind the returned value
 * which may be an Application Framework function. If the return value is
 * non-null, please make sure that you call the returned function from your
 * handler to avoid negating the resource cleanup of the Application Framework
 * itself.
 *
 */
void emberAfMainInitCallback(void)
{
  emberEventControlSetActive(commissioningLedEventControl);
}

/** @brief Complete
 *
 * This callback is fired when the Network Steering plugin is complete.
 *
 * @param status On success this will be set to EMBER_SUCCESS to indicate a
 * network was joined successfully. On failure this will be the status code of
 * the last join or scan attempt. Ver.: always
 * @param totalBeacons The total number of 802.15.4 beacons that were heard,
 * including beacons from different devices with the same PAN ID. Ver.: always
 * @param joinAttempts The number of join attempts that were made to get onto
 * an open Zigbee network. Ver.: always
 * @param finalState The finishing state of the network steering process. From
 * this, one is able to tell on which channel mask and with which key the
 * process was complete. Ver.: always
 */
void emberAfPluginNetworkSteeringCompleteCallback(EmberStatus status,
                                                  uint8_t totalBeacons,
                                                  uint8_t joinAttempts,
                                                  uint8_t finalState)
{
  emberAfCorePrintln("%p network %p: 0x%X", "Join", "complete", status);

  if (status != EMBER_SUCCESS) {
    // Initialize our ZLL security now so that we are ready to be a touchlink
    // target at any point.
    status = emberAfZllSetInitialSecurityState();
    if (status != EMBER_SUCCESS) {
      emberAfCorePrintln("Error: cannot initialize ZLL security: 0x%X", status);
    }

    status = emberAfPluginNetworkCreatorStart(false); // distributed
    emberAfCorePrintln("%p network %p: 0x%X", "Form", "start", status);
  }
}

/** @brief Complete
 *
 * This callback notifies the user that the network creation process has
 * completed successfully.
 *
 * @param network The network that the network creator plugin successfully
 * formed. Ver.: always
 * @param usedSecondaryChannels Whether or not the network creator wants to
 * form a network on the secondary channels Ver.: always
 */
void emberAfPluginNetworkCreatorCompleteCallback(const EmberNetworkParameters *network,
                                                 bool usedSecondaryChannels)
{
  emberAfCorePrintln("%p network %p: 0x%X",
                     "Form distributed",
                     "complete",
                     EMBER_SUCCESS);
}

/** @brief On/off Cluster Server Post Init
 *
 * Following resolution of the On/Off state at startup for this endpoint, perform any
 * additional initialization needed; e.g., synchronize hardware state.
 *
 * @param endpoint Endpoint that is being initialized  Ver.: always
 */
void emberAfPluginOnOffClusterServerPostInitCallback(uint8_t endpoint)
{
  // At startup, trigger a read of the attribute and possibly a toggle of the
  // LED to make sure they are always in sync.
  emberAfOnOffClusterServerAttributeChangedCallback(endpoint,
                                                    ZCL_ON_OFF_ATTRIBUTE_ID);
}

/** @brief Server Attribute Changed
 *
 * On/off cluster, Server Attribute Changed
 *
 * @param endpoint Endpoint that is being initialized  Ver.: always
 * @param attributeId Attribute that changed  Ver.: always
 */
void emberAfOnOffClusterServerAttributeChangedCallback(uint8_t endpoint,
                                                       EmberAfAttributeId attributeId)
{
  // When the on/off attribute changes, set the LED appropriately.  If an error
  // occurs, ignore it because there's really nothing we can do.
  if (attributeId == ZCL_ON_OFF_ATTRIBUTE_ID) {
    bool onOff;
    if (emberAfReadServerAttribute(endpoint,
                                   ZCL_ON_OFF_CLUSTER_ID,
                                   ZCL_ON_OFF_ATTRIBUTE_ID,
                                   (uint8_t *)&onOff,
                                   sizeof(onOff))
        == EMBER_ZCL_STATUS_SUCCESS) {
      if (onOff) {
        halSetLed(ON_OFF_LIGHT_LED);
      } else {
        halClearLed(ON_OFF_LIGHT_LED);
      }
    }
  }
}

/** @brief Hal Button Isr
 *
 * This callback is called by the framework whenever a button is pressed on the
 * device. This callback is called within ISR context.
 *
 * @param button The button which has changed state, either BUTTON0 or BUTTON1
 * as defined in the appropriate BOARD_HEADER.  Ver.: always
 * @param state The new state of the button referenced by the button parameter,
 * either ::BUTTON_PRESSED if the button has been pressed or ::BUTTON_RELEASED
 * if the button has been released.  Ver.: always
 */
void emberAfHalButtonIsrCallback(uint8_t button, uint8_t state)
{
  if (state == BUTTON_RELEASED) {
    emberEventControlSetActive(findingAndBindingEventControl);
  }
}

void print_hex(uint8_t *buf,uint8_t len)
{
	if(len==0)
		return;
	else{
		emberAfCorePrintln("%x",*buf);
		return print_hex(++buf,len-1);
	}
}

uint8_t private_key = {0x31,0x51,0xb5,0xad,0x0c,0x3f,0x08,0x36,
					   0x0c,0xe3,0x71,0xba,0x26,0x16,0x44,0xd5,
					   0x08,0xf5,0x0e,0x68,0x80,0xb1,0x31,0xd6,
					   0x21,0x65,0xbc,0x41,0x6f,0x50,0x93,0x39};


#define PUBKEY_OFFSET_X (0x34A)
#define PUBKEY_OFFSET_Y (0x36A)
/*
 * verify_image()
 * verifies an image of arbitrary size
 *  image - pointer to the image to be verified
 *  size -
 *
 * */
void verify_image(uint8_t *image, size_t image_size, uint8_t *signature, size_t siglen, int * result)
{
	mbedtls_sha256_context sha256ctx;
	mbedtls_ecdsa_context verify;
	mbedtls_ecdsa_context ecdsa;
	uint8_t hash[32];
	uint8_t pubKeyFromMfgToken[65];
	mbedtls_mpi r,s;
	uint8_t buf[200];
	size_t sig_len;

//	mbedtls_ctr_drbg_context ctr_drbg;


//	mbedtls_ctr_drbg_init(&ctr_drbg);

	memset(buf,0xff,200);

	if(image==NULL || image_size == 0 || result == NULL || signature == NULL ){
		*result = -1;
		return;
	}
	mbedtls_sha256_init(&sha256ctx);
	mbedtls_sha256_starts_ret(&sha256ctx,false);
	*result = mbedtls_sha256_update_ret(&sha256ctx,image,image_size);
	if(*result != 0){
		return;
	}
	mbedtls_sha256_finish_ret(&sha256ctx,hash);
	if(*result != 0){
			return;
	}
    mbedtls_ecdsa_init(&verify);
    mbedtls_ecdsa_init(&ecdsa);
	mbedtls_ecp_group_init(&verify.grp);
	mbedtls_ecp_group_init(&ecdsa.grp);
	*result = mbedtls_ecp_group_load(&verify.grp,MBEDTLS_ECP_DP_SECP256R1);
	if(*result!=0){
		emberAfCorePrintln("error load ECP group\r\n");
		return;
	}

	*result = mbedtls_ecp_group_load(&ecdsa.grp,MBEDTLS_ECP_DP_SECP256R1);
		if(*result!=0){
			emberAfCorePrintln("error load ECP group\r\n");
			return;
		}
	//halCommonGetMfgToken(&verify.Q,);
	/*get the X co-ordinate of the device public key and import it*/
	pubKeyFromMfgToken[0] = 0x04;
	memcpy(pubKeyFromMfgToken+1,LOCKBITS_BASE+PUBKEY_OFFSET_X,32);
	//mbedtls_ecp_point_read_binary(&verify.grp,&verify.Q.X,pubKeyFromMfgToken,32);
	/*get the Y co-ordinate of the device public key and import it*/
	memcpy(pubKeyFromMfgToken+33,LOCKBITS_BASE+PUBKEY_OFFSET_Y,32);
	*result = mbedtls_ecp_point_read_binary(&verify.grp,&verify.Q,pubKeyFromMfgToken,65);
	if(*result){
			emberAfCorePrintln("error reading pubkey\r\n");
			return;
		}//mbedtls_ecp_point_lset(&verify.Q.Z,1);
/*
	*result = mbedtls_ecp_point_read_binary(&ecdsa.grp,&verify.Q,pubKeyFromMfgToken,65);
		if(*result){
				emberAfCorePrintln("error reading pubkey\r\n");
				return;
			}//mbedtls_ecp_point_lset(&verify.Q.Z,1);
*/
	*result = mbedtls_ecp_check_pubkey(&verify.grp,&verify.Q);
	if(*result){
		emberAfCorePrintln("error checking pubkey\r\n");
		return;
	}
/*
	*result = mbedtls_ecp_check_pubkey(&ecdsa.grp,&verify.Q);
		if(*result){
			emberAfCorePrintln("error checking pubkey\r\n");
			return;
		}
*/

	/* read in the signature and verify the hash of the image using the device public key*/
    *result = mbedtls_ecdsa_read_signature(&verify,hash,sizeof(hash),signature,siglen);
    if(*result){
    	emberAfCorePrintln("error reading/verifying signature\r\n");
    }

    print_hex(hash,32);


//    *result = mbedtls_ecdsa_sign(&ecdsa.grp,&r,&s,private_key,hash,32,mbedtls_ctr_drbg_random,&ctr_drbg);


//	*result = mbedtls_ecdsa_sign(&verify.grp,&r,&s,&verify.d,hash,32,NULL,NULL);

    emberAfCorePrintln("result=%d\n",*result);

    emberAfCorePrintln("r:");

    print_hex(&r,32);

    emberAfCorePrintln("s:");

    print_hex(&s,32);

//    siglen = 71;

//    mbedtls_ecdsa_write_signature(&ecdsa,MBEDTLS_MD_SHA256,hash,32,buf,&siglen,NULL,NULL);
//    print_hex(buf,32);
    /*clean up*/
    mbedtls_ecdsa_free(&verify);
    mbedtls_sha256_free(&sha256ctx);
}


void runImageVerifyTest(void){
	 uint8_t message[] = {0xa3,0xd3, 0xb3, 0x81, 0x58, 0x67 , 0x2e , 0xea , 0xe2 ,
			             0x62 , 0xce , 0x0a , 0xd1 , 0xd4 , 0x56 , 0xed , 0xb0,
			             0xa2 , 0x10 , 0x8f , 0xfe , 0xe7 , 0x0c , 0x6f , 0x2e ,
						 0xf1 , 0x3f , 0x3a , 0x8a , 0x2b , 0x68 , 0x69};

	 uint8_t signature[] = {0x30,0x45, 0x02, 0x20,
            0x70, 0xf1 , 0x33 , 0x0d , 0x0e , 0x32 , 0x43 , 0x08
			, 0xe7 , 0x86 , 0x89 , 0xd4 , 0xb9 , 0x9d , 0x38 , 0x8b
			, 0xd9 , 0x5b , 0x00 , 0xce , 0x45 , 0xec , 0x32 , 0x84
			, 0x7b , 0xa3 , 0x87 , 0xee , 0x79 , 0x43 , 0xf8 , 0xeb,
			0x02,0x21,0x00, 0x9e , 0x6b , 0xbc , 0x8d , 0x6f , 0xc9 , 0x3e , 0x7d
			, 0x36 , 0xe1 , 0xf1 , 0x62 , 0x6e , 0x29 , 0x56 , 0x04
			, 0x0f , 0x00 , 0xe9 , 0x2b , 0x92 , 0x0b , 0xcd , 0x09
			, 0xd1 , 0x58 , 0xc4 , 0xfb , 0x29 , 0x81 , 0x73 , 0xb6};
	int16_t result;
	emberAfCorePrintln("result of verifying image is: %2x\r\n",result);
	verify_image(message,sizeof(message),signature,sizeof(signature),&result);
	emberAfCorePrintln("result of verifying image is: %2x\r\n",result);

}
