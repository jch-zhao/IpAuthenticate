package com.wsddata.ipa;
import java.io.IOException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class IpAuthentication implements Filter{
	private String ipAllow=null;
	
	@Autowired
	private Config conf;
	
	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		ipAllow = conf.ip_allow;
	}
	
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		//HttpServletRequest req=(HttpServletRequest) request;
		HttpServletResponse resp=(HttpServletResponse) response;
		String clientIP=request.getRemoteAddr();
		String permitIP=ipAllow;
		if(judgeIP(clientIP,permitIP)){
			chain.doFilter(request, response);
		}else{
			resp.sendError(403);
		}
	}
	@Override
	public void destroy() {
		this.ipAllow=null;
	}
	
	private boolean judgeIP(String clientIP,String permitIP){
		boolean permit=false;
		if(permitIP==null||clientIP==null||permitIP==""||clientIP=="")
			return permit;
		
		String[] ips=permitIP.trim().split(";");
		for(String ip:ips){
			if(ip.equals("*")){
				permit=true;
				break;
			}
			if(ip.contains("-")){
				String start=ip.substring(0,ip.indexOf("-"));
				String end=ip.substring(ip.indexOf("-")+1,ip.length());
				permit=permit||judgeIPRange(clientIP,start,end);
			}else{
				if(ip.contains("*")){
					String start=ip.replace("*","001");
					String end=ip.replace("*","255");
					permit=permit||judgeIPRange(clientIP,start,end);
				}else{
					if(ip.equals(clientIP)){
						permit=permit||true;
					}
				}
			}
		}
		return permit;
	}
	
	private boolean judgeIPRange(String clientIP,String startIP,String endIP){
		String[] clientIP_seg=clientIP.trim().split("\\.");
		String charClientIP="";
		for(int i=0;i<clientIP_seg.length;i++){
			int bits=clientIP_seg[i].length();
			if(bits==1){
				clientIP_seg[i]="00"+clientIP_seg[i];
			}else if(bits==2){
				clientIP_seg[i]="0"+clientIP_seg[i];
			}
			charClientIP=charClientIP+clientIP_seg[i];
		}
		long numClientIP=0l;
		try{
			numClientIP=Long.parseLong(charClientIP);
		}catch(Exception e){
			numClientIP=0l;
		}
				
		String[] start_seg=startIP.trim().split("\\.");
		String charStart="";
		for(int i=0;i<start_seg.length;i++){
			int bits=start_seg[i].length();
			if(start_seg[i].equals("*")){
				start_seg[i]="001";
			}else if(bits==1){
				start_seg[i]="00"+start_seg[i];
			}else if(bits==2){
				start_seg[i]="0"+start_seg[i];
			}
			charStart=charStart+start_seg[i];
		}
		long numStart=Long.parseLong(charStart);
		
		String[] end_seg=endIP.trim().split("\\.");
		String charEnd="";
		for(int i=0;i<end_seg.length;i++){
			int bits=end_seg[i].length();
			if(end_seg[i].equals("*")){
				end_seg[i]="255";
			}else if(bits==1){
				end_seg[i]="00"+end_seg[i];
			}else if(bits==2){
				end_seg[i]="0"+end_seg[i];
			}
			charEnd=charEnd+end_seg[i];
		}
		long numEnd=Long.parseLong(charEnd);
		if(numClientIP>=numStart&&numClientIP<=numEnd){
			return true;
		}else{
			return false;
		}
	}
	
}
