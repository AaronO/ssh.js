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
							"byte["+(packageInfo.packetLength-packageInfo.paddingLength-1)+"]","payload",
							"byte["+packageInfo.paddingLength+"]","padding",
							"byte[0]","mac"
						));						
					}
				}
			});
		});	
		
		self.on("packet",function(p){
			var command = p.payload[0];
			console.log("got command "+command+" length: "+p.payload.length);
			switch(command){
				case 20:
					keyExchange(p);	
					break;
			}
		});
		
		function keyExchange(p){
			console.log("reading...");
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
					"byte[]",d.cookie,
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
				),
				padding:new Buffer(0),
				mac:new Buffer(0)
			});
			
			/*
			sendPackage({
				payload:pack(
					"byte",30,
					"mpint",
			});*/
			
		}	
		
		function sendPackage(p){
		
			var pkg = pack(
				"uint32",p.payload.length+p.padding.length+p.mac.length+1,
				"byte",p.padding.length,
				"byte[]",p.payload,
				"byte[]",p.padding,
				"byte[]",p.mac
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
				//needs to be implemented in future
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