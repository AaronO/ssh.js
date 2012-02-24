var net = require("net");
var crypto = require("crypto");
var assert = require("assert");

module.exports.connect = function(ip){
	return new Connection(ip);
}

function Connection(ip){
	var buffer = new Buffer(0);
	
	//information about server & client
	var clientVersion = "2.0";
	var clientName = "ssh.js";
	var clientComment = "";	
	var serverVersion;
	var serverName;
	var serverComment;
	
	//information for key exchange & encryption
	var serverIdentification;	//V_S
	var clientIdentification;	//V_C
	var serverKexinitMessage;	//I_S
	var clientKexinitMessage;	//I_C
	var publicHostKey;			//K_S
	var sharedSecret;			//K
	var exchangeHash;			//H
	var sessionIdentifier;
	var key = new Buffer("A");

	
	//the diffie hellman object used to generate the keys
	var hellman;
	
	var encrypted = false;
	
	var self = net.connect(22,ip,function(){
		self.once("data",function(d){
			
			//get server information
			serverIdentification = d.slice(0,d.length-2);			
			var si = serverIdentification.toString("binary").substr(4);
			serverVersion = si.substr(0,si.indexOf("-"));
			si = si.substr(si.indexOf("-")+1).split(" ");
			serverName = si[0];
			serverComment = si.slice(1).join(" ");
			
			//send client information
			clientIdentification = new Buffer("SSH-"+clientVersion+"-"+clientName+(clientComment.length?(" "+clientComment):""),"binary");
			self.write(clientIdentification.toString("binary")+"\r\n");
			
			//start packet reading			
			self.on("data",function(d){
				var b = new Buffer(buffer.length+d.length);
				buffer.copy(b);
				d.copy(b,buffer.length);
				buffer = b;
				
				if(buffer.length >= 5){
					var packageInfo = read(buffer,0,
						"uint32","packetLength",
						"byte","paddingLength"
					);
					if(buffer.length >= packageInfo.packetLength+4){
						self.emit("packet",buffer.slice(5,4+packageInfo.packetLength-packageInfo.paddingLength));						
						buffer = buffer.slice(4+packageInfo.length);
					}
				}
			});
			
					
		});	
		
		self.on("packet",function(p){
			var command = p[0];
			switch(command){
				case 1:
					disconnect(p);
					break;
				case 21:
					changeKey();
					break;
				case 20:
					keyExchange(p);	
					break;
				case 31:
					continueKeyExchange(p);
					break;
					
			}
		});
		
		function disconnect(p){
			var d = read(p,1,
				"uint32","code",
				"string","description",
				"string","language"
			);
			self.emit("disconnect",d);
		}
		
		function keyExchange(p){
			var d = read(serverKexinitMessage = p,1,
				"byte[16]","cookie",
				"name-list","kexAlgorithms",
				"name-list","serverHostKeyAlgorithms",
				"name-list","encryptionAlgorithmsClient",
				"name-list","encryptionAlgorithmsServer",
				"name-list","macAlgorithmsClient",
				"name-list","macAlgorithmsServer",
				"name-list","compressionAlgorithmsClient",
				"name-list","compressionAlgorithmsServer",
				"name-list","languagesClient",
				"name-list","languagesServer",
				"boolean","firstKexPacketFollows",
				"uint32","reserved"				
			);
			
			sendPackage(clientKexinitMessage = pack(
				"byte",20,
				"byte[]",new Buffer(16),
				"name-list",["diffie-hellman-group1-sha1","diffie-hellman-group14-sha1"],
				"name-list",["ssh-dss"],
				"name-list",["3des-cbc"],
				"name-list",["3des-cbc"],
				"name-list",["hmac-sha1"],
				"name-list",["hmac-sha1"],
				"name-list",["none"],
				"name-list",["none"],
				"name-list",[],
				"name-list",[],
				"boolean",false,
				"uint32",0
			));	

			hellman = crypto.getDiffieHellman("modp2");
			hellman.generateKeys();		
			
			sendPackage(pack(
				"byte",30,
				"mpint",new Buffer(hellman.getPublicKey(),"binary")
			));
		}

		function continueKeyExchange(p){
			var d = read(p,1,
				"string","K_S",
				"mpint","f",
				"string","SigH"
			);			
			
			exchangeHash = pack(
				"string",clientIdentification.toString("binary"),
				"string",serverIdentification.toString("binary"),
				"string",clientKexinitMessage.toString("binary"),
				"string",serverKexinitMessage.toString("binary"),
				"string",(publicHostKey = d.K_S).toString("binary"),
				"mpint",new Buffer(hellman.getPublicKey(),"binary"),
				"mpint",d.f,
				"mpint",(sharedSecret = new Buffer(hellman.computeSecret(d.f.toString("binary")),"binary"))
			);
			
			var hash = crypto.createHash("sha1");
			hash.update(exchangeHash.toString("binary"));
			exchangeHash = new Buffer(hash.digest(),"binary");
			
			if(!sessionIdentifier){
				sessionIdentifier = exchangeHash;
			}
			
			sendPackage(pack(
				"byte",21
			));
			encrypted = true;
		}
		
		function changeKey(){
			key = pack(
				"byte[]",sharedSecret,
				"byte[]",exchangeHash,
				"byte[]",key,
				"byte[]",sessionIdentifier
			);
			var hash = crypto.createHash("sha1");
			hash.update(key.toString("binary"));
			key = new Buffer(key.digest(),"binary");
		}
		
		function sendPackage(p){	
		
			var l = 5+p.length;
			while(l < 16 || l%8 != 0){
				l++;
			}
			var padding = new Buffer(l-p.length-5);
		
			var pkg = pack(
				"uint32",l-4,
				"byte",padding.length,
				"byte[]",p,
				"byte[]",padding
			);			

			require("fs").writeFileSync("c:/out.txt",pkg);
			self.write(pkg);
		}
		
	});
	
	return self;
}

function pack(){
	var buffers = [];
	for(var i = 0; i < arguments.length; i+= 2){
		var type = arguments[i];
		var value = arguments[i+1];
		
		switch(type){
			case "byte":
				buffers.push(new Buffer([value]));
				break;
			case "boolean":
				buffers.push(new Buffer([value?1:0]));
				break;
			case "uint32":
				var buffer = new Buffer(4);
				var r = value%256;
				buffer[3] = r;
				value -= r;
				value /= 256;
				r = value%256;
				buffer[2] = r;
				value -= r;
				value /= 256;
				r = value%256;
				buffer[1] = r;
				value -= r;
				value /= 256;
				buffer[0] = value;
				buffers.push(buffer);
				break;
			case "string":
			case "name-list":
			case "mpint":
				if(type == "name-list"){
					value = new Buffer(value.join(","),"binary");
				}else if(type == "string"){
					value = new Buffer(value,"binary");
				}
				buffers.push(pack("uint32",value.length));
				buffers.push(value);
				break;
			case "byte[]":
				buffers.push(value);
				break;				
		}
	}

	var size = 0;
	for(var i = 0; i < buffers.length; i++){
		size += buffers[i].length;
	}
	var buffer = new Buffer(size);
	var index = 0;
	for(var i = 0; i < buffers.length; i++){		
		buffers[i].copy(buffer,index);
		index += buffers[i].length;
	}
	return buffer;	
}
function read(b, index){
	var results = {};
	var result;
	for(var i = 2; i < arguments.length; i+=2){
		var type = arguments[i];
		var name = arguments[i+1];

		switch(type){
			case "byte":
				result = b[index++];
				break;
			case "boolean":
				result = b[index++] == 1;
				break;
			case "uint32":
				result = b.readUInt32BE(index);
				index += 4;
				break;
			case "uint64":
				result = null;
				index += 8;
				break;
			case "string":
			case "name-list":
			case "mpint":
				var s = "";
				var buffer = b.slice(index+4,index+4+b.readUInt32BE(index));
				index += 4+buffer.length;
				
				if(type == "name-list"){
					result = buffer.toString("binary").split(",");
				}else if(type == "mpint"){
					result = buffer;
				}else{
					result = buffer.toString("binary");
				}
				break;
			default:
				if(type.indexOf("byte[") == 0){
					var buffer = new Buffer(parseInt(type.substring(5,type.length-1),10));
					b.copy(buffer,0,index,index+buffer.length);
					index += buffer.length;
					result = buffer;
				}
				break;
		}
		results[name] = result;
	}
	return results;
}