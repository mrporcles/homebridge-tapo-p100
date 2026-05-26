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
    
    // Note: TPAP implementation temporarily disabled - requires complete SPAKE2+ crypto implementation
    // For firmware 1.4.0+, enable "Third-Party Compatibility" in Tapo app to use KLAP/Legacy protocols
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
  }

  private handleAuthenticationFailure(): void {
    const deviceHost = this.accessory.context.device.host;
    this.log.error(`🚫 All authentication methods failed for device: ${deviceHost}`);
    this.log.error('');
    this.log.error('📱 For firmware 1.4.0+ devices (HTTP 403 Forbidden errors):');
    this.log.error('   🔧 Third-Party Compatibility Setup:');
    this.log.error('   1. Open Tapo app → Select this device');
    this.log.error('   2. Settings → Advanced Settings');
    this.log.error('   3. Find "Third-Party Compatibility" and enable it');
    this.log.error('   4. If already enabled: toggle OFF, wait 10 sec, toggle ON');
    this.log.error('   5. Power cycle the device (unplug for 10 seconds)');
    this.log.error('   6. Wait 2 minutes, then restart Homebridge');
    this.log.error('');
    this.log.error('📡 Additional troubleshooting:');
    this.log.error('   - Ensure device firmware is up to date');
    this.log.error('   - Try factory reset if Third-Party Compatibility option missing');
    this.log.error('   - Verify correct IP address: ' + deviceHost);
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