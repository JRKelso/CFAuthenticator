<cfscript>
epoch = CreateDateTime(1970,1,1,0,0,0);

function getEpochTime(timeObj){
	utcTimeZone = createObject("java", "java.util.TimeZone").getTimeZone(javaCast("string", "Etc/UTC"));
	utcTime = createObject("java", "java.util.GregorianCalendar").init(utcTimeZone);
	utcTime.set(javaCast("int", year(timeOBj)), javaCast("int", month(timeObj)-1), javaCast("int", day(timeObj)), javaCast("int", hour(timeObj)), javaCast("int", minute(timeObj)), second(timeObj));
	utcTime.set(javaCast("int", utcTime.MILLISECOND), javaCast("int", 0));
	return utcTime.getTimeInMillis()/1000;
}

testDate1 = createDateTime(2005,03,18,1,58,29);
testDate2 = createDateTime(2005,3,18,1,58,31);
testDate3 = createDateTime(2009,02,13,23,31,30);
testDate4 = createDateTime(2033,05,18,03,33,20);
//Now() = createDateTime(2011,3,11,3,30,0);
testDate5 = createDateTime(2603, 10, 11, 11, 33, 20);
//epochTime = dateDiff("s", epoch, testDate4);
epochTime = getEpochTime(now());
writeDump(epochTime);
timeStep = Int(epochTime/30);
writeDump(timeStep);
while (Len(timeStep) < 16){
	timeStep = "0" & timeStep;
}
longObj = createObject("java", "java.lang.Long");
steps = longObj.toHexString(javaCast("long", timeStep)).ToUpperCase();
writeDump(steps);
sharedKey = "12345678901234567890";
sharedKey = charsetDecode(sharedKey, "utf-8");
sharedKey = binaryEncode(sharedKey, "hex");
keyBytes = createObject("java", "java.math.BigInteger").init("10" & sharedKey, 16).ToByteArray();
for (i = 1; i < arrayLen(keyBytes); i++){
	keyBA[i] = keyBytes[i+1];
}
while (len(steps) < 16){
	steps = "0" & steps;
}
timeByteArray = createObject("java", "java.math.BigInteger").init("10" & steps, 16).toByteArray();
for (i = 1; i < ArrayLen(timeByteArray); i++){
	timeBA[i] = timeByteArray[i+1];
}
keySpec = createObject("java", "javax.crypto.spec.SecretKeySpec").init(keyBA, "HmacSHA1");
mac = createObject("java", "javax.crypto.Mac").getInstance(keySpec.getAlgorithm());
mac.init(keySpec);
hotpMessage = mac.doFinal(timeBA);
offset = bitAnd(hotpMessage[arrayLen(hotpMessage)], inputBaseN("f", 16)) + 1;
otpTest = hotpMessage[offset] & hotpMessage[offset + 1] & hotpMessage[offset + 2] & hotpMessage[offset + 3];
firstOffset = bitSHLN(bitAnd(hotpMessage[offset], inputBaseN("7f", 16)), 24);
secondOffset = bitSHLN(bitAnd(hotpMessage[offset + 1], 255), 16);
thirdOffset = bitSHLN(bitAnd(hotpMessage[offset + 2], 255), 8);
fourthOffset = bitAnd(hotpMessage[offset + 3], 255);
binary = bitOr(bitOr(firstOffset, secondOffset), bitOr(thirdOffset, fourthOffset));
writedump(Mid(binary, len(binary)-5, 6));
//binary = bitAnd(hotpMessage[offset], inputBaseN("7f",16)) & bitAnd(hotpMessage[offset + 1], inputBaseN("ff", 16)) & bitAnd(hotpMessage[offset + 2], inputBaseN("ff", 16)) & bitAnd(hotpMessage[offset + 3], inputBaseN("ff", 16));
//writeDump(binary);
//writeDump(BitAnd(inputBaseN(offsetHex, 16), inputBaseN("7fffffff", 16)));
</cfscript>
