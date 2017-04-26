package com.wsddata.ipa;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class Config{
	@Value("${ip.allow}")
	public String ip_allow;
	
	@Value("${ip.applyPath}")
	public String ipApplyPath;
}
