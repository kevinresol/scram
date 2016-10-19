package scram;

import haxe.io.Bytes;
import haxe.crypto.Hmac;
import haxe.crypto.Sha1;
import haxe.crypto.Sha256;
import haxe.crypto.Base64;

// Client-side implementation of SCRAM (RFC5802) https://tools.ietf.org/html/rfc5802
class ScramClient {
	
	public var clientFirstMessage(default, null):String;
	public var serverFirstMessage(default, set):String;
	public var clientFinalMessage(default, null):String;
	public var serverFinalMessage(default, set):String;
	
	var user:String;
	var password:String;
	var hmac:Hmac;
	var method:HashMethod;
	
	var clientFirstMessageBare:String;
	var serverSignature:Bytes;
	
	public function new(user:String, password:String, method:HashMethod, ?nonce:String) {
		this.user = user;
		this.password = password;
		this.method = method;
		this.hmac = new Hmac(method);
		
		if(nonce == null) {
			var buf = new StringBuf();
			for(i in 0...20) buf.addChar(Std.random(80) + 45); // random ascii chars except `,`
			nonce = buf.toString();
		}
		clientFirstMessageBare = 'n=$user,r=$nonce';
		clientFirstMessage = 'n,,$clientFirstMessageBare';
	}
	
	function xorBytes(a:Bytes, b:Bytes) {
		inline function min(a:Int, b:Int) return a > b ? b : a;
		var length = min(a.length, b.length);
		var result = Bytes.alloc(length);
		var a = a.getData();
		var b = b.getData();
		for(i in 0...length) result.set(i, Bytes.fastGet(a, i) ^ Bytes.fastGet(b, i));
		return result;
	}
	
	function pbkdf2Hmac(value:Bytes, salt:Bytes, iterations:Int) {
		
		#if nodejs
		
		// native implementation is way faster...
		var length = 0, digest = null;
		switch method {
			case SHA1:
				length = 20;
				digest = 'sha1';
			case SHA256:
				length = 32;
				digest = 'sha256';
			default:
		}
		return js.node.Crypto.pbkdf2Sync(js.node.Buffer.hxFromBytes(value), js.node.Buffer.hxFromBytes(salt), iterations, length, digest).hxToBytes();
		
		#else
		
		// salt
		var buf = new haxe.io.BytesBuffer();
		buf.add(salt);
		buf.addByte(0);
		buf.addByte(0);
		buf.addByte(0);
		buf.addByte(1);
		var salt = buf.getBytes();
		
		var u = hmac.make(value, salt);
		var t = u;
		
		for(i in 0...iterations - 1) {
			t = hmac.make(value, t);
			u = xorBytes(u, t);
		}
		return u;
		
		#end
	} 
	
	function set_serverFirstMessage(v:String) {
		serverFirstMessage = v;
		
		var serverNonce = null, salt = null, iterations = 0;
		for(item in v.split(',')) {
			var index = item.indexOf('=');
			var value = item.substr(index + 1);
			switch item.substr(0, index) {
				case 'r': serverNonce = value;
				case 's': salt = Base64.decode(value);
				case 'i': iterations = Std.parseInt(value);
			}
		}
		
		var clientFinalMessageWithoutProof = 'c=biws,r=$serverNonce';
		var saltedPassword = pbkdf2Hmac(Bytes.ofString(password), salt, iterations);
		var clientKey = hmac.make(saltedPassword, Bytes.ofString('Client Key'));
		var storedKey = switch method {
			case SHA1: Sha1.make(clientKey);
			case SHA256: Sha256.make(clientKey);
			default: throw 'Unsupported hash method';
		}
		var authMessage = '$clientFirstMessageBare,$serverFirstMessage,$clientFinalMessageWithoutProof';
		var clientSignature = hmac.make(storedKey, Bytes.ofString(authMessage));
		var clientProof = xorBytes(clientKey, clientSignature);
		var serverKey = hmac.make(saltedPassword, Bytes.ofString('Server Key'));
		serverSignature = hmac.make(serverKey, Bytes.ofString(authMessage));
		clientFinalMessage = '$clientFinalMessageWithoutProof,p=${Base64.encode(clientProof)}';
		return v;
	}
	
	function set_serverFinalMessage(v:String) {
		serverFinalMessage = v;
		
		for(item in v.split(',')) {
			var index = item.indexOf('=');
			var value = item.substr(index + 1);
			switch item.substr(0, index) {
				case 'v': if(Base64.encode(serverSignature) != value) throw InvalidServerSignature;
			}
		}
		
		return v;
	}
}

enum Error {
	InvalidServerSignature;
}