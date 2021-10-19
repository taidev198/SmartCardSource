package FinalProject;

// import javacard.framework.*;
// import javacard.framework.APDU;
// import javacard.security.KeyBuilder;
// import javacard.security.*;
// import javacardx.crypto.*;
import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
import javacardx.apdu.ExtendedLength;
public class FinalProject extends Applet implements ExtendedLength
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
	public final static  byte GENDER = (byte)0x06;
	public final static  byte ID_DEPARTMENT = (byte)0x07;
	
//decode
    private static final short NIBBLE_SIZE = 4;

    public static final short REASON_DATA_BUFFER_NOT_LARGE_ENOUGH = 0x0001;
    public static final short REASON_INVALID_ENCODING_SIZE = 0x0002;
    public static final short REASON_INVALID_ENCODING_CHARACTER = 0x0003;
    public static final short REASON_INVALID_DATA_SIZE = 0x0004;
    
    //rsa
	private static final byte EXPORT_PUBK_MODU =(byte) 0x10;
	private static final byte EXPORT_PUBK_EXPO =(byte) 0x11;
	private static final byte SIGN_DATA = (byte) 0x12;
	private RSAPrivateKey rsaPrivKey;
	private RSAPublicKey rsaPubKey;
	private Signature rsaSig;
	private short sigLen;
	private byte[] sig_buffer;
    
    //ins_avatar
    private static final byte INS_LOAD_IMAGE = 0x21;
	private static final byte INS_SEND_IMAGE = 0x22;
    
	byte[] name;
	byte[] id;
	byte[] date;
	byte[] address;
	byte[] gender;
	byte[] id_department;
	
	//avatar
		private static byte [] avatar;
	private static short avatarLength;
	private static final short MAX_AVATAR_SIZE = 25120;
	
	
	public   FinalProject(byte[] bArray, short bOffset, byte bLength) 
	{
		
		
		sigLen = (short)(KeyBuilder.LENGTH_RSA_1024/8);
		sig_buffer = new byte[sigLen];
		
		rsaSig = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1,false);
		
		//Xay dung ban mau cho cac khoa
		rsaPrivKey = (RSAPrivateKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, (short)(8*sigLen),false); 
		rsaPubKey = (RSAPublicKey)KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, (short)(8*sigLen), false);
		//Tu ban mau o tren, tao ra bo doi khoa cong khai bi mat lien quan mat thiet den nhau
		KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA, (short)(8*sigLen));
		keyPair.genKeyPair();
		rsaPrivKey = (RSAPrivateKey)keyPair.getPrivate();
		rsaPubKey = (RSAPublicKey)keyPair.getPublic();
		
        // Util.arrayCopy(bArray, (short)(bOffset +1), pinTemp, (short)0, MAX_PIN_SIZE);
        //pinTemp = new byte[] {0x01,0x02,0x03,0x04,0x05};
        
         mDig = MessageDigest.getInstance(MessageDigest.ALG_MD5, true);
        short ret =  mDig.doFinal(bArray, (short)(bOffset +1),MAX_PIN_SIZE, pinTemp,(short)0 );
         pin = new OwnerPIN(PIN_TRY_LIMIT, (byte)ret);
         //fromUppercaseHex(bArray, (short)0, (short)16, pinTemp,(short)0);
        // convertToDec(pinTemp, (short)16);
          pin.update(pinTemp,(short)( 0), (byte)ret);
          volatileMem = JCSystem.makeTransientByteArray((short) 0x10, JCSystem.CLEAR_ON_DESELECT);
         nonVolatileMem = new byte[(short) 0x10];
         aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);
         aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        aesKey.setKey(pinTemp, (short)0);
        name = new  byte[30];
        id = new byte[30];
        date = new byte[30];
        address = new byte[30];
        gender = new byte[30];
        id_department = new byte[30];
        //avatar
        avatar = new byte[MAX_AVATAR_SIZE];
		Util.arrayFillNonAtomic(avatar,(short)0,MAX_AVATAR_SIZE,(byte)0x00);
        
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
	
		short len = apdu.setIncomingAndReceive();
		switch (buffer[ISO7816.OFFSET_INS])
		{
			
		
		 case (byte)0x09:
			mDig.reset();
			short ret = mDig.doFinal(buffer, ISO7816.OFFSET_CDATA, (short)5, buffer, (short)0);
			 Util.arrayCopy(pinTemp, (short)0, buffer, (short)0, (short)16);
			  apdu.setOutgoingAndSend((short)0, (short)16);
                  break;
         case INS_ENCRYPT:
                 aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
                 aesCipher.doFinal(buffer, ISO7816.OFFSET_CDATA, (short) 0x10, volatileMem, (short) 0x00);
                 switch(buffer[ISO7816.OFFSET_P1]) {
				 case ID:
				  Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, id, (short) 0x00, (short) 0x10);
				 	break;
				case NAME:
				  Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, name, (short) 0x00, (short) 0x10);
				 	break;
				 	case DATE:
				  Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, date, (short) 0x00, (short) 0x10);
				 	break;
				 	case ADDRESS:
				  Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, address, (short) 0x00, (short) 0x10);
				 	break;
				 	case GENDER:
				  Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, gender, (short) 0x00, (short) 0x10);
				 	break;
				 	case ID_DEPARTMENT:
				  Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, id_department, (short) 0x00, (short) 0x10);
				 	break;
				 case 0x11:
				Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, buffer, (short) 0x00, (short) 0x10);
				 apdu.setOutgoingAndSend((short) 0x00, (short) 0x10);
				 break;
                 }
              break;
         case INS_DECRYPT:
                 aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
                 switch(buffer[ISO7816.OFFSET_P1]) {
				 case ID:
				 aesCipher.doFinal(id, (short)0, (short) 0x10, volatileMem, (short) 0x00);
				  Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, buffer, (short) 0x00, (short) 0x10);
				 	apdu.setOutgoingAndSend((short) 0x00, (short) 0x10);
				 	break;
				case NAME:
				  aesCipher.doFinal(name, (short)0, (short) 0x10, volatileMem, (short) 0x00);
				  Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, buffer, (short) 0x00, (short) 0x10);
				 	apdu.setOutgoingAndSend((short) 0x00, (short) 0x10);
				 	break;
				 	case DATE:
				  aesCipher.doFinal(date, (short)0, (short) 0x10, volatileMem, (short) 0x00);
				  Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, buffer, (short) 0x00, (short) 0x10);
				 	apdu.setOutgoingAndSend((short) 0x00, (short) 0x10);
				 	break;
				 	case ADDRESS:
				  aesCipher.doFinal(address, (short)0, (short) 0x10, volatileMem, (short) 0x00);
				  Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, buffer, (short) 0x00, (short) 0x10);
				 	apdu.setOutgoingAndSend((short) 0x00, (short) 0x10);
				 	break;
				 	case GENDER:
				  aesCipher.doFinal(gender, (short)0, (short) 0x10, volatileMem, (short) 0x00);
				  Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, buffer, (short) 0x00, (short) 0x10);
				 	apdu.setOutgoingAndSend((short) 0x00, (short) 0x10);
				 	break;
				 	case ID_DEPARTMENT:
				  aesCipher.doFinal(id_department, (short)0, (short) 0x10, volatileMem, (short) 0x00);
				  Util.arrayCopyNonAtomic(volatileMem, (short) 0x00, buffer, (short) 0x00, (short) 0x10);
				 	apdu.setOutgoingAndSend((short) 0x00, (short) 0x10);
				 	break;
                 }
                 break;
        
        case EXPORT_PUBK_MODU:
				exportPublicModulus(apdu);
			break;
		case EXPORT_PUBK_EXPO:
				exportPublicExponent(apdu);
			break;
		case SIGN_DATA:
				signData(apdu);
			break;
        case INS_LOAD_IMAGE: //0x0C
				loadImage(apdu, len); 
				break;
			case INS_SEND_IMAGE: //0x0D
				sendImage(apdu, len);
				break;
        case VERIFY: verify(apdu);
              break;
        case CHANGE_PIN:
        	//mDig.reset();
        //	mDig.doFinal(buffer, ISO7816.OFFSET_CDATA, (short)16, buffer, (short)0);
        	pin.update(buffer, ISO7816.OFFSET_CDATA, (byte)16);
        	apdu.setOutgoingAndSend((short)0, (short)16);
        	break;
        case RESET_PIN:
        	resetPin();
        	break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}


	
	private void resetPin(){
		pin.resetAndUnblock();
	}
	
	private void verify(APDU apdu) {
		if( pin.getTriesRemaining() != 0 )	{
			 byte[] buffer = apdu.getBuffer();
      
           if ( !pin.check(buffer, ISO7816.OFFSET_CDATA, (byte)16) )
               ISOException.throwIt(SW_VERIFICATION_FAILED);
		  }	else  ISOException.throwIt(SW_OVER_ATTEMP);
    }
    
    private void exportPublicModulus(APDU apdu) {
		byte buffer[] = apdu.getBuffer();
		short expLenmo = rsaPubKey.getModulus(buffer, (short) 0);
		apdu.setOutgoingAndSend((short) 0, (short) (expLenmo));
	}
	
	private void exportPublicExponent(APDU apdu) {
		byte buffer[] = apdu.getBuffer();
		short expLenex = rsaPubKey.getExponent(buffer, (short) 0);
		apdu.setOutgoingAndSend((short) 0, (short) expLenex);
	}
	
	private void signData(APDU apdu){
		byte buffer[] = apdu.getBuffer();
		
		rsaSig.init(rsaPrivKey, Signature.MODE_SIGN);
		rsaSig.sign(buffer, (short)5, (short)20, sig_buffer, (short)0);
		apdu.setOutgoing();
		apdu.setOutgoingLength((short)(sigLen));
		apdu.sendBytesLong(sig_buffer, (short)0, sigLen);
	}

    
     private void loadImage(APDU apdu, short len){
		 byte[] buffer = apdu.getBuffer();
		 //lay do dai du lieu gui xuong
		 short dataLength = apdu.getIncomingLength();
		 Util.arrayFillNonAtomic(avatar,(short)0,MAX_AVATAR_SIZE,(byte)0x00);
		 // apdu.setOutgoing();
		 // Util.arrayFillNonAtomic(buffer,(short)0,(short)10,(byte)0x00);
		 // Util.setShort(buffer,(short) 0, dataLength);
		 // apdu.setOutgoingLength((short)5);
		 // apdu.sendBytes((short)0,(short)5);
		 
		 if(dataLength > MAX_AVATAR_SIZE){
			 ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		 }
		 short dataOffset = apdu.getOffsetCdata();
		 short pointer = 0;
		 while (len > 0){
			 Util.arrayCopy(buffer,dataOffset,avatar,pointer,len);
			 pointer += len;
			 len = apdu.receiveBytes(dataOffset);
		 }
		avatarLength = (short)pointer;

		apdu.setOutgoing();


		// Util.setShort(buffer,(short) 0, avatarBlock);
		// apdu.setOutgoingLength((short)5);
		// apdu.sendBytes((short)0,(short)5);
			//Cai dat che do ma hoa cho du lieu moi
		aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
		aesCipher.doFinal(avatar,(short)0,MAX_AVATAR_SIZE,avatar,(short)0);	 
	 }
	 
	 private void sendImage(APDU apdu, short len){
		 if(avatarLength == (short) 0){
			 ISOException.throwIt(ISO7816.SW_RECORD_NOT_FOUND);
		 }
		 aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
		 aesCipher.doFinal(avatar,(short) 0, MAX_AVATAR_SIZE, avatar,(short) 0);
		 short toSend = avatarLength;
		 short le = apdu.setOutgoing();
		 apdu.setOutgoingLength(MAX_AVATAR_SIZE);
		 short sendLen = 0;
		 short pointer = 0;
		 while(toSend > 0){
			 sendLen = (toSend > 0) ? le : toSend;
			 apdu.sendBytesLong(avatar,pointer,sendLen);
			 toSend -= sendLen;
			 pointer += sendLen;
		 }
		//Anh gui ra sau do se duoc ma hoa va luu lai vao bien
		aesCipher.init(aesKey, Cipher.MODE_ENCRYPT);
		aesCipher.doFinal(avatar,(short)0,MAX_AVATAR_SIZE,avatar,(short)0);	
	 }
    
}
