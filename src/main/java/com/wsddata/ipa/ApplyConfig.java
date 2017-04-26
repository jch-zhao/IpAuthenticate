package com.wsddata.ipa;

import java.util.ArrayList;
import java.util.Collection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import com.wsddata.ipa.IpAuthentication;

@Configuration
public class ApplyConfig {
	@Autowired
	private Config conf;

	@Bean
	public FilterRegistrationBean regAuthFilter(IpAuthentication filter) {
	    FilterRegistrationBean registration = new FilterRegistrationBean(filter);
	    registration.setOrder(FilterRegistrationBean.REQUEST_WRAPPER_FILTER_MAX_ORDER+1);
	    Collection<String> urlPatterns=new ArrayList<String>();
	    String applyPath=conf.ipApplyPath;
	    if(applyPath!=null&&!applyPath.equals("")){
	    	String[] applyPaths=applyPath.split(";");
	    	if(applyPaths.length>0){
		    	for(int i=0;i<applyPaths.length;i++){
		    		if(!applyPaths[i].equals("")&&applyPaths[i].startsWith("/")){
		    			urlPatterns.add(applyPaths[i]);
		    			System.out.println("ip检查应用在： "+applyPaths[i]);
		    		}
		    	}
		    }
	    }
	    
	    registration.setUrlPatterns(urlPatterns);//只对需要认证的服务进行验证
	    return registration;
	}
}
