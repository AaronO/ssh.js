var net = require("net");

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
				console.log(d+"");
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
						self.emit("packet",read(buffer,5,
							"byte["+(packageInfo.packetLength-packageInfo.paddingLength-1)+"]","payload"/*,
							"byte["+packageInfo.paddingLength+"]","padding",
							"byte[0]","mac"*/
						));
						
						buffer = buffer.slice(4+packageInfo.length);
					}
				}
			});
			
			
			
			
			
			
		});	
		
		self.on("packet",function(p){
			var command = p.payload[0];
			switch(command){
				case 1:
					disconnect(p);
					break;
				case 20:
					keyExchange(p);	
					break;
			}
		});
		
		function disconnect(p){
			var d = read(p.payload,1,
				"uint32","code",
				"string","description",
				"string","language"
			);
			self.emit("disconnect",d);
		}
		
		function keyExchange(p){
			var d = read(p.payload,1,
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
			
			sendPackage({
				payload:pack(
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
					"boolean",true,
					"uint32",0
				),
				padding:new Buffer(10),
				mac:new Buffer(0)
			});
			
					
			
			self.write(new Buffer([0,0,0,12,6,30,0,0,16,0,0,0,0,0,0,0]));
			
			/*
			console.log("sent");
			
			var p = 23;
			var g = 5;
			var x = 6;
			var e = Math.pow(g,x)%p;
			
			console.log(e);
			
			
			
			sendPackage({
				payload:pack(
					"byte",30,
					"mpint",e
				)
			});*/
			
		}	
		
		function sendPackage(p){
		
		
			var l = 5+p.payload.length;
			while(l < 16 || l%8 != 0){
				l++;
			}
			var padding = new Buffer(l-p.payload.length-5);

		
			var pkg = pack(
				"uint32",l-4,
				"byte",padding.length,
				"byte[]",p.payload,
				"byte[]",padding
			);
			
			console.log("packet lengt: "+pkg.length);
			console.log("packet: ",pkg);
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
				if(type == "name-list"){
					value = value.join(",");
				}
				value = new Buffer(value,"binary");
				buffers.push(pack("uint32",value.length));
				buffers.push(value);
				break;
			case "byte[]":
				buffers.push(value);
				break;
			case "mpint":
				var length = 1;
				while(value > Math.pow(256,length++));
				length--;				
				buffers.push(new Buffer([0,0,0,1]));
				var buffer = new Buffer(length);
				console.log("val:"+value);
				for(var i = buffer.length-1; i >= 0; i--){
					buffer[i] = value%256;
					console.log("buf:"+buffer[i]);
					value -= buffer[i];
					value /= 256;
				}
				buffers.push(buffer);				
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
				var s = "";
				var buffer = new Buffer(b.readUInt32BE(index));
				index += 4;
				b.copy(buffer,0,index,index+buffer.length);
				index += buffer.length;
				result = buffer+"";
				
				if(type == "name-list"){
					result = result.split(",");
				}
				break;
			case "mpint":			
				var length = (b[index]*256*256+b[index+1]*256+b[index+2])/8;
				var val = 0;
				for(var j = 0; j < length; j++){
					val += b[index+3+j]*Math.pow(256,length-j-1);					
				}
				var h = Math.pow(256,length)/2;
				if(val > h){
					val = -(val-h);
				}					
				result = val;
				index += 3+length;			
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
		results[arguments[i+1]] = result;
	}
	return results;
}