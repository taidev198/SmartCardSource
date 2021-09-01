package FinalProject;

import javacard.framework.*;
import javacard.security.KeyBuilder;
import javacard.security.*;
import javacardx.crypto.*;
public class FinalProject extends Applet
{

    // codes of INS byte in the command APDU header
    final static byte VERIFY = (byte)0x20;
 
    // maximum number of incorrect tries before the PIN is blocked
    final static byte PIN_TRY_LIMIT =(byte)0x03;

    // maximum size PIN
    final static byte MAX_PIN_SIZE =(byte)0x05;

    // signal that the PIN verification failed
    final static short SW_VERIFICATION_FAILED = 0x6300;
    
    final static short SW_OVER_ATTEMP = 0x6303;

    // signal the the PIN validation is required
    // for a credit or a debit transaction
    final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;


 //variables declaration */
   static OwnerPIN pin;
	
	//init for cryto
	 static Cipher aesCipher;
   static AESKey aesKey;
    //Two different types of memory for different usage. each one has 16 (= 0x10) byte capacity.
    private byte[] volatileMem;
    private byte[] nonVolatileMem;
    
    MessageDigest mDig;
    private byte[] pinCode;
    

//INS value for APDU command
    public final  static  byte INS_SET_KEY = (byte)0x01;
    public final static  byte INS_ENCRYPT = (byte)0x02;
    public final static  byte INS_DECRYPT = (byte)0x03;
//PIN ins
	public final static  byte RESET_PIN = (byte)0x04;
	public final static  byte CHANGE_PIN = (byte)0x05;
     byte[] pinTemp = new byte[16];
      
      
// INS FOR USER'S INFOR
	public final static  byte ID = (byte)0x01;
	public final static  byte NAME = (byte)0x02;	
     public final static  byte DATE = (byte)0x03;
	public final static  byte ADDRESS = (byte)0x04;
	public final static  byte AVATAR = (byte)0x05;
	
//decode
    private static final short NIBBLE_SIZE = 4;

    public static final short REASON_DATA_BUFFER_NOT_LARGE_ENOUGH = 0x0001;
    public static final short REASON_INVALID_ENCODING_SIZE = 0x0002;
    public static final short REASON_INVALID_ENCODING_CHARACTER = 0x0003;
    public static final short REASON_INVALID_DATA_SIZE = 0x0004;
    
	byte[] name;
	byte[] id;
	byte[] date;
	byte[] address;
	
	public   FinalProject(byte[] bArray, short bOffset, byte bLength) 
	{
		
        // Util.arrayCopy(bArray, (short)(bOffset +1), pinTemp, (short)0, MAX_PIN_SIZE);
        //pinTemp = new byte[] {0x01,0x02,0x03,0x04,0x05};
        
         mDig = MessageDigest.getInstance(MessageDigest.ALG_MD5, true);
        short ret =  mDig.doFinal(bArray, (short)(bOffset +1),MAX_PIN_SIZE, pinTemp,(short)0 );
         pin = new OwnerPIN(PIN_TRY_LIMIT, (byte)ret);
         //fromUppercaseHex(bArray, (short)0, (short)16, pinTemp,(short)0);
        // convertToDec(pinTemp, (short)16);
          pin.update(pinTemp,(short)( 0), (byte)ret);
          volatileMem = JCSystem.makeTransientByteArray((short) 0x20, JCSystem.CLEAR_ON_DESELECT);
         nonVolatileMem = new byte[(short) 0x10];
         aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
         aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        aesKey.setKey(pinTemp, (short)0);
        name = new  byte[30];
        id = new byte[30];
        date = new byte[30];
        address = new byte[30];
        
        register();
	}
	
 public static void install(byte[] bArray, short bOffset, byte bLength){
        // create a Wallet applet instance
        new FinalProject(bArray, bOffset, bLength);
    } // end of install method

    public boolean select() {
        // The applet declines to be selected if the pin is blocked.
        if( pin.getTriesRemaining() == 0 )
            return false;

        return true;
    }// end of select method

    public void deselect() {
        // reset the pin value
        pin.reset();
    }

	public void process(APDU apdu)
	{
		if (selectingApplet())
		{
			return;
		}

		byte[] buffer = apdu.getBuffer();
		 apdu.setIncomingAndReceive();
		switch (buffer[ISO7816.OFFSET_INS])
		{
			
		
		 case (byte)0x09:
			// // Util.arrayCopy(pinTemp, (short)0, buffer, (short)0, MAX_PIN_SIZE);
			 // // pin.update(pinTemp,(short)0, MAX_PIN_SIZE);
			// // apdu.setOutgoingAndSend((short) 0x00, MAX_PIN_SIZE);
			mDig.reset();
			short ret = mDig.doFinal(buffer, ISO7816.OFFSET_CDATA, (short)5, buffer, (short)0);
			
			 Util.arrayCopy(pinTemp, (short)0, buffer, (short)0, (short)16);
			  apdu.setOutgoingAndSend((short)0, (short)16);
			// break;
         // case INS_SET_KEY:
					// pinTemp = new byte[] {0x01,0x02,0x03,0x04,0x05};
                 // aesKey.setKey(buffer, ISO7816.OFFSET_CDATA);
                  break;
         case INS_ENCRYPT:
                 aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
                 aesCipher.doFinal(buffer, ISO7816.OFFSET_CDATA, (short) 0x20, volatileMem, (short) 0x00);
                 switch(buffer[ISO7816.OFFSET_P1]) {
				 case ID:
				  Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, id, (short) 0x00, (short) 0x20);
				 	break;
				case NAME:
				  Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, name, (short) 0x00, (short) 0x20);
				 	break;
				 	case DATE:
				  Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, date, (short) 0x00, (short) 0x20);
				 	break;
				 	case ADDRESS:
				  Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, address, (short) 0x00, (short) 0x20);
				 	break;
				 case 0x11:
				Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, buffer, (short) 0x00, (short) 0x20);

				 apdu.setOutgoingAndSend((short) 0x00, (short) 0x20);
				 break;
                 }
                
              break;
         case INS_DECRYPT:
                 aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
                 switch(buffer[ISO7816.OFFSET_P1]) {
				 case ID:
				 aesCipher.doFinal(id, (short)0, (short) 0x20, volatileMem, (short) 0x00);
				  Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, buffer, (short) 0x00, (short) 0x20);
				 	apdu.setOutgoingAndSend((short) 0x00, (short) 0x20);
				 	break;
				case NAME:
				  aesCipher.doFinal(name, (short)0, (short) 0x20, volatileMem, (short) 0x00);
				  Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, buffer, (short) 0x00, (short) 0x20);
				 	apdu.setOutgoingAndSend((short) 0x00, (short) 0x20);
				 	break;
				 	case DATE:
				  aesCipher.doFinal(date, (short)0, (short) 0x20, volatileMem, (short) 0x00);
				  Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, buffer, (short) 0x00, (short) 0x20);
				 	apdu.setOutgoingAndSend((short) 0x00, (short) 0x20);
				 	break;
				 	case ADDRESS:
				  aesCipher.doFinal(address, (short)0, (short) 0x20, volatileMem, (short) 0x00);
				  Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, buffer, (short) 0x00, (short) 0x20);
				 	apdu.setOutgoingAndSend((short) 0x00, (short) 0x20);
				 	break;
                 }
                 break;
        
        case VERIFY: verify(apdu);
              break;
        case CHANGE_PIN:
        	//mDig.reset();
        //	mDig.doFinal(buffer, ISO7816.OFFSET_CDATA, (short)16, buffer, (short)0);
        	pin.update(buffer, ISO7816.OFFSET_CDATA, (byte)16);
        	apdu.setOutgoingAndSend((short)0, (short)16);
        	break;
              
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	
	private void encriptProcess(APDU apdu) {
		
      Cipher aesCipher;
  AESKey aesKeyTrial;
  aesKeyTrial= (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);
  byte[] buffer = apdu.getBuffer();
  byte[] aesKey;
  aesKey = new byte[16];
  byte[] input = {(byte)0x11,(byte)0x22,(byte)0x33,(byte)0x44,(byte)0x55,(byte)0x66,(byte)0x77,(byte)0x88,(byte)0x99,0x10,(byte)0xA2, 0x35, (byte)0x5E,0x15,0x16,0x14};
  byte[] key = {0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26};

  short len = (short) input.length;
  if (len <= 0 || len % 16 != 0)
    {
        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    }

  aesKeyTrial.setKey(key,(short)0);
  aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
  aesCipher.init(aesKeyTrial, Cipher.MODE_ENCRYPT); 
  aesCipher.doFinal(input, (short)0, len, buffer, (short)0);
  apdu.setOutgoingAndSend((short)0, len);	
	}
	
	private void verify(APDU apdu) {
		if( pin.getTriesRemaining() != 0 )	{
			 byte[] buffer = apdu.getBuffer();
      
           if ( !pin.check(buffer, ISO7816.OFFSET_CDATA, (byte)16) )
               ISOException.throwIt(SW_VERIFICATION_FAILED);
		  }	else  ISOException.throwIt(SW_OVER_ATTEMP);
    }
    
}
