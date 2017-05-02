package edu.mit.kit.repository.impl;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import javax.naming.NamingException;
import javax.naming.directory.Attributes;

import org.mitre.openid.connect.model.DefaultUserInfo;
import org.mitre.openid.connect.model.UserInfo;
import org.mitre.openid.connect.repository.UserInfoRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapTemplate;

import com.google.common.base.Strings;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.util.concurrent.UncheckedExecutionException;
import org.springframework.security.ldap.search.LdapUserSearch;

/**
 * Looks up the user information from an LDAP template and maps the results
 * into a UserInfo object. This object is then cached.
 * 
 * @author jricher
 *
 */

// TODO: Make this class more pluggable and configurable

public class LdapUserInfoRepository implements UserInfoRepository {

	private String ldapUserCacheDurationMs = "2000";

	private LdapTemplate ldapTemplate;

	private String emailSuffix = "@example.com";
	
	public LdapTemplate getLdapTemplate() {
		return ldapTemplate;
	}

	public void setLdapTemplate(LdapTemplate ldapTemplate) {
		this.ldapTemplate = ldapTemplate;
	}

	private LdapUserSearch ldapUserSearch;

	public LdapUserSearch getLdapUserSearch() {
		return ldapUserSearch;
	}

	public void setLdapUserSearch(LdapUserSearch ldapUserSearch) {
		this.ldapUserSearch = ldapUserSearch;
	}

	public String getLdapUserCacheDurationMs() {
		return ldapUserCacheDurationMs;
	}

	public void setLdapUserCacheDurationMs(String ldapUserCacheDurationMs) {
		this.ldapUserCacheDurationMs = ldapUserCacheDurationMs;
	}

	/**
	 * Logger for this class
	 */
	private static final Logger logger = LoggerFactory.getLogger(LdapUserInfoRepository.class);

	//
	// This code does the heavy lifting that maps the LDAP attributes into UserInfo attributes
	//

	private AttributesMapper attributesMapper = new AttributesMapper() {
		@Override
		public Object mapFromAttributes(Attributes attr) throws NamingException {

			UserInfo ui = new DefaultUserInfo();

			if (attr.get("uid") != null) {
				// save the UID as the preferred username
				ui.setPreferredUsername(attr.get("uid").get().toString());

				// for now we use the UID as the subject as well (this should probably be different)
				ui.setSub(attr.get("uid").get().toString());
			} else if (attr.get("sAMAccountName") != null) {
				// save the UID as the preferred username
				ui.setPreferredUsername(attr.get("sAMAccountName").get().toString());

				// for now we use the UID as the subject as well (this should probably be different)
				ui.setSub(attr.get("sAMAccountName").get().toString());
			} else if (attr.get("cn") != null) {
				// save the UID as the preferred username
				ui.setPreferredUsername(attr.get("cn").get().toString());

				// for now we use the UID as the subject as well (this should probably be different)
				ui.setSub(attr.get("cn").get().toString());
			} else {
				return null;
			}

			// add in the optional fields

			// email address
			if (attr.get("mail") != null) {
				ui.setEmail(attr.get("mail").get().toString());
				// if this domain also provisions email addresses, this should be set to true
				ui.setEmailVerified(false);
			}

			// phone number
			if (attr.get("telephoneNumber") != null) {
				ui.setPhoneNumber(attr.get("telephoneNumber").get().toString());
				// if this domain also provisions phone numbers, this should be set to true
				ui.setPhoneNumberVerified(false);
			}

			// name structure
			if (attr.get("displayName") != null) {
				ui.setName(attr.get("displayName").get().toString());
			}

			if (attr.get("givenName") != null) {
				ui.setGivenName(attr.get("givenName").get().toString());
			}

			if (attr.get("sn") != null) {
				ui.setFamilyName(attr.get("sn").get().toString());
			}

			if (attr.get("initials") != null) {
				ui.setMiddleName(attr.get("initials").get().toString());
			}

			if (attr.get("labeledURI") != null) {
				ui.setProfile(attr.get("labeledURI").get().toString());
			}

			if (attr.get("organizationName") != null) {
				ui.setWebsite(attr.get("organizationName").get().toString());
			}

			return ui;

		}
	};

	// lookup result cache, key from username to userinfo
	private LoadingCache<String, UserInfo> cache;

	private CacheLoader<String, UserInfo> ldapUserSearchCacheLoader = new CacheLoader<String, UserInfo>() {
		public UserInfo load(String username) throws Exception {
			DirContextOperations searchedForUser = ldapUserSearch.searchForUser(username);

			if (searchedForUser == null) {
				// user not found, error
				return null;
			} else {
				// user found
				UserInfo userInfo = (UserInfo) attributesMapper.mapFromAttributes(searchedForUser.getAttributes());
				return userInfo;
			}
		}
	};

	
	public LdapUserInfoRepository() {
		this.cache = CacheBuilder.newBuilder()
					.maximumSize(100)
					.expireAfterAccess(14, TimeUnit.DAYS)
					.build(cacheLoader);
	}
	
	
	@Override
	public UserInfo getByUsername(String username) {
		try {
			return cache.get(username);
		} catch (UncheckedExecutionException ue) {
			return null;
		} catch (ExecutionException e) {
			e.printStackTrace();
			return null;
		}
	}

	/**
	 * Strip off the suffix defined in emailSuffix and use the rest as a username
	 */
	/* (non-Javadoc)
	 * @see org.mitre.openid.connect.repository.UserInfoRepository#getByEmailAddress(java.lang.String)
	 */
	@Override
	public UserInfo getByEmailAddress(String email) {
		if (!Strings.isNullOrEmpty(email)) {
			if (email.endsWith(getEmailSuffix())) {
				String username = email.substring(0, email.length() - getEmailSuffix().length());
				return getByUsername(username);
			} else {
				// email doesn't match, end
				return null;
			}
		} else {
			// email was null, end
			return null;
		}
	}

	/**
	 * @return the emailSuffix
	 */
	public String getEmailSuffix() {
		return emailSuffix;
	}

	/**
	 * @param emailSuffix the emailSuffix to set
	 */
	public void setEmailSuffix(String emailSuffix) {
		this.emailSuffix = emailSuffix;
	}

}
