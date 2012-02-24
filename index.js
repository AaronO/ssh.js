var net = require("net");
var crypto = require("crypto");
var assert = require("assert");

module.exports.connect = function(ip){
	return new Connection(ip);
}

function Connection(ip){
	var buffer = new Buffer(0);
	
	var clientID = "SSH-2.0-PuTTY_Release_0.61";
	var serverID = "";
	
	var self = net.connect(22,ip,function(){
		self.once("data",function(d){
			serverID = (d+"").substr(0,d.length-2);
			self.write(clientID+"\r\n");
			
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
				case 20:
					keyExchange(p);	
					break;
				case 31:
					continueKeyExchange(p);
					
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
			var d = read(p,1,
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
			
			sendPackage(pack(
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
			
			
                                             

            var hellman = crypto.createDiffieHellman('ANz5OguIOXLsDhmYmsWizjEOHTdxfo2Vcbt2I3MYZuYe91ouJ4mLBX+YkcLiemOcPym2CBRYHNOyyjmG0mg3BVd9RcLn5S3IHHoXGHblzqdLFEi/368Ygo79JRnxTkXjgmY0rxlJ5bU1zIKaSDuKdiI+XUkKJX8Fvf8W8vsixYOr',"base64");
			hellman.setPrivateKey(crypto.randomBytes(20));
			hellman.generateKeys();
			
			var e = hellman.getPublicKey();
			var x = hellman.getPrivateKey();		
			
			sendPackage(pack(
				"byte",30,
				"mpint",new Buffer(e,"binary")
			));
		}

		function continueKeyExchange(p){
			var d = read(p,1,
				"string","K_S",
				"mpint","f",
				"string","SigH"
			);
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