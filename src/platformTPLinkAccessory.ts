import { CharacteristicGetCallback, CharacteristicSetCallback, CharacteristicValue, Logger, PlatformAccessory, Service } from 'homebridge';
import type { TapoPlatform } from './platform.js';
import { TpLinkAccessory } from './utils/tplinkAccessory.js';

export abstract class TPLinkPlatformAccessory <T extends TpLinkAccessory>{ 

  protected tpLinkAccessory!: T;
  protected service!: Service;

  constructor(
    public readonly log: Logger,
    protected readonly platform: TapoPlatform,
    protected readonly accessory: PlatformAccessory,
    protected readonly timeout: number,
    protected readonly updateInterval?: number,
  ) {
    this.log.debug('Start adding accessory: ' + accessory.context.device.host);
  }

  protected initialise(platform: TapoPlatform, updateInterval?: number):void{
    this.log.debug(`Starting authentication for device: ${this.accessory.context.device.host}`);
    
    // Try TPAP first for firmware 1.4.3+ devices (based on python-kasa implementation)
    this.tpLinkAccessory.handshake_tpap().then(() => {
      this.log.info('✅ TPAP authentication successful (firmware 1.4.3+)');
      this.init(platform, updateInterval);
    }).catch((tpapError: Error) => {
      this.log.debug('TPAP handshake failed, trying KLAP/Legacy:', tpapError.message);
      
      // Fallback to KLAP/Legacy protocols
      this.tpLinkAccessory.handshake().then(() => {
      if(this.tpLinkAccessory.is_klap){
          setTimeout(()=>{
            this.tpLinkAccessory.handshake_new().then(() => {
              this.log.info('✅ KLAP authentication successful');
              this.init(platform, updateInterval);
            }).catch((klapError) => {
              this.setNoResponse();
              this.log.error('❌ KLAP Handshake failed:', (klapError as Error).message);
              this.handleAuthenticationFailure();
              this.tpLinkAccessory.is_klap = false;
            });
          }, 100);
        } else{
          this.tpLinkAccessory.login().then(() => {
            this.log.info('✅ Legacy authentication successful');
            this.init(platform, updateInterval);
          }).catch((legacyError) => {
            this.setNoResponse();
            this.log.error('❌ Legacy login failed:', (legacyError as Error).message);
            this.handleAuthenticationFailure();
          });
        }
    }).catch((handshakeError) => {
      const errorMsg = (handshakeError as Error).message;
      if (errorMsg.includes('403')) {
        this.log.info('Got 403 Forbidden - trying direct KLAP authentication for firmware 1.4.0+');
        // For firmware 1.4.0+ devices, try KLAP directly after 403
        this.tpLinkAccessory.is_klap = true;
        this.tpLinkAccessory.handshake_new().then(() => {
          this.log.info('✅ KLAP authentication successful after 403');
          this.init(platform, updateInterval);
        }).catch((klapError) => {
          this.setNoResponse();
          this.log.error('❌ KLAP failed after 403:', (klapError as Error).message);
          this.handleAuthenticationFailure();
        });
      } else {
        this.setNoResponse();
        this.log.error('❌ Initial handshake failed:', errorMsg);
        this.handleAuthenticationFailure();
      }
    });
    }).catch((finalError) => {
      this.setNoResponse();
      this.log.error('❌ All authentication methods failed:', (finalError as Error).message);
      this.handleAuthenticationFailure();
    });
  }

  private handleAuthenticationFailure(): void {
    const deviceHost = this.accessory.context.device.host;
    this.log.error(`🚫 All authentication methods failed for device: ${deviceHost}`);
    this.log.error('');
    this.log.error('⚠️  FIRMWARE 1.4.6 DETECTED: This firmware is currently NOT SUPPORTED');
    this.log.error('   Firmware 1.4.6 blocks ALL local API access, even with Third-Party Compatibility');
    this.log.error('');
    this.log.error('🔧 SOLUTIONS:');
    this.log.error('   Option 1: Check Tapo app for firmware version');
    this.log.error('   - If 1.4.6: Consider downgrading firmware (if manufacturer allows)');
    this.log.error('   - If 1.4.0 or below: Enable Third-Party Compatibility in Tapo app');
    this.log.error('');
    this.log.error('   Option 2: Use Matter integration instead');
    this.log.error('   - Some devices support Matter protocol as alternative');
    this.log.error('   - Check device manual for Matter compatibility');
    this.log.error('');
    this.log.error('   Option 3: Wait for TP-Link or community TPAP implementation');
    this.log.error('   - Monitor plugin updates for future firmware 1.4.6 support');
    this.log.error('');
    this.log.error('📍 Device IP: ' + deviceHost + ' - Check firmware in Tapo app');
  }

  protected abstract init(platform: TapoPlatform, updateInterval?: number):void;

  /**
   * Handle "SET" requests from HomeKit
   * These are sent when the user changes the state of an accessory.
   */
  setOn(value: CharacteristicValue, callback: CharacteristicSetCallback) {
    this.tpLinkAccessory.setPowerState(value as boolean).then((result) => {
      if(result){
        this.platform.log.debug('Set Characteristic On ->', value);
        this.tpLinkAccessory.getSysInfo().device_on = value as boolean;
        // you must call the callback function
        callback(null);
      } else{
        callback(new Error('unreachable'), false);
      }
    }).catch((error) => {
      this.log.error('Failed to set power state: ' + error);
      callback(new Error('unreachable'), false);
    });
  }

  /**
   * Handle the "GET" requests from HomeKit
   * These are sent when HomeKit wants to know the current state of the accessory.
   * 
   */
  getOn(callback: CharacteristicGetCallback) {
    // implement your own code to check if the device is on
    this.tpLinkAccessory.getDeviceInfo().then((response) => {
      if(response){
        const isOn = response.device_on;

        this.platform.log.debug('Get Characteristic On ->', isOn);
  
        // you must call the callback function
        // the first argument should be null if there were no errors
        // the second argument should be the value to return
        // you must call the callback function
        if(isOn !== undefined){
          callback(null, isOn);
        } else{
          callback(new Error('unreachable'), isOn);
        }
      } else{
        callback(new Error('unreachable'), false);
      }
    }).catch((error) => {
      this.log.debug('error: ' + error);

      callback(new Error('unreachable'), 0);
    });
  }

  protected updateState(interval:number){
    this.platform.log.debug('Updating state');
    this.tpLinkAccessory.getDeviceInfo(true).then((response) => {
      if(response){
        const isOn = response.device_on;

        this.platform.log.debug('Get Characteristic On ->', isOn);
  
        if(isOn !== undefined){
          this.service.updateCharacteristic(this.platform.Characteristic.On, isOn);
        } else{
          this.platform.log.debug('On is undefined -> set no response');
          this.setNoResponse();
        }

        setTimeout(()=>{
          this.updateState(interval);
        }, interval);
      } else{
        this.setNoResponse();
        interval += 300000;
        setTimeout(()=>{
          this.updateState(interval);
        }, interval);
      }
    }).catch(()=>{
      this.setNoResponse();
      setTimeout(()=>{
        this.updateState(interval + 300000);
      }, interval);
    });
  }

  protected setNoResponse():void{
    this.service.updateCharacteristic(this.platform.Characteristic.On, new Error('unreachable'));
  }
}