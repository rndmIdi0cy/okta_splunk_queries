## Login actions
```
index=sso sourcetype="okta:im"
| fields src_ip, user, "action.objectType", "action.requestUri" 
| table src_ip, user, "action.objectType", "action.requestUri"
| rename src_ip As "Source IP", user As "Username", "action.objectType" As "Action", "action.requestUri" As "Requested URL"
```

## Okta Login Activity Trend
```
index=sso sourcetype="okta:im" event_type="okta_event_authentication"
| timechart span=10m count by action
```

## Top User Agents requesting authentications
```
index=sso sourcetype="okta:im" event_type="okta_event_authentication"
| spath output=UserAgent path=actors{}.id
| eval UserAgent=mvindex(UserAgent,-1)
| stats count by UserAgent
| sort -count
| head 10
```

## Get Blacklisted Addresses
```
index=sso sourcetype="okta:im" "action.objectType"="security.zone.request.blocked"
| table requestId, src_ip, "action.requestUri"
| rename requestId As "Request ID", src_ip As "Source IP", "action.requestUri" As "Requested URL"
```

## Successful SSO Authentications
```
index=sso sourcetype="okta:im" event_type="okta_event_authentication" "action.objectType"="app.auth.sso"
| eval timestamp=strftime(_time,"%Y-%m-%d %H:%M:%S") 
| spath output=UserAgent path=actors{}.id
| spath output=DisplayName path=actors{}.displayName 
| spath output=ActorUsername path=actors{}.login
| spath output=TargetUsername path=targets{}.login
| eval UserAgent=mvindex(UserAgent,-1)
| eval ActorUsername=mvindex(ActorUsername,-1)
| eval TargetUsername=mvindex(TargetUsername,-1)
| eval DisplayName=mvindex(DisplayName,0)
| table timestamp, DisplayName, ActorUsername, TargetUsername, src_ip, app, UserAgent, "action.requestUri"
| rename timestamp As "Timestamp" DisplayName As "Display Name" ActorUsername As "Actor Username" TargetUsername As "Target Username" src_ip As "Source IP" app As "Application" UserAgent As "User Agent" "actdion.requestUri" As "Requested URL"
```

## Failed Okta Login
```
index=sso sourcetype="okta:im" event_type="okta_event_authentication" action="failure"
| eval timestamp=strftime(_time,"%Y-%m-%d %H:%M:%S") 
| spath output=Actor path=targets{}.displayName
| eval Actor=mvindex(Actor,0) 
| eval Actor=case(isnull(Actor),"Unknown User",true(),Actor)
| spath output=UserAgent path=actors{}.id
| eval UserAgent=mvindex(UserAgent,-1) 
| table timestamp, user, Actor, src_ip, "action.message", UserAgent, app
| rename timestamp As "Timestamp", user As "Username", Actor As "Display Name", src_ip As "Source IP", "action.message" As "Description", UserAgent As "User Agent", app As "Provider"
```

## Success Logins
```
index=sso sourcetype="okta:im" event_type="okta_event_authentication" action="success"
| eval timestamp=strftime(_time,"%Y-%m-%d %H:%M:%S") 
| eval Actor=mvindex($targets{}.displayName$,0) 
| eval Actor=case(isnull(Actor),"Unknown User",true(),Actor)
| eval UserAgent=mvindex($actors{}.id$,-1) 
| table timestamp, user, Actor, src_ip, "action.message", UserAgent, app
| rename timestamp As "Timestamp", user As "Username", Actor As "Display Name", src_ip As "Source IP", "action.message" As "Description", UserAgent As "User Agent", app As "Provider"
```

## Lockout
```
index=sso source="Okta:im2" ((eventType="user.authentication.auth_via_AD_agent" AND "outcome.reason"="Authentication failed: account is locked") OR (eventType="user.session.start" AND "outcome.reason"="LOCKED_OUT")) user="*"
| eval timestamp=strftime(_time,"%Y-%m-%d %H:%M:%S")
| spath output=targetUserName path=target{}.alternateId
| spath output=targetDisplayName path=target{}.displayName
| eval targetUserName=mvindex(targetUserName,0)
| eval targetUserName=case(isnull(targetUserName),"N/A",true(),targetUserName)
| eval targetDisplayName=mvindex(targetDisplayName,0)
| eval targetDisplayName=case(isnull(targetDisplayName),"N/A",true(),targetDisplayName)
| table timestamp, user, actor.displayName, targetUserName, targetDisplayName, src_ip, client.geographicalContext.state, displayMessage, outcome.reason
| rename timestamp As "Timestamp", user As "Username", actor.displayName As "Display Name", targetUserName As "Affected Username", targetDisplayName As "Affected User", src_ip As "Source IP", client.geographicalContext.state As "Origin State", displayMessage As "Event", "outcome.reason" As "Reason"
```

## MFA Enroll Requests
```
index=sso source="Okta:im2" eventType="policy.evaluate_sign_on" "outcome.reason"="Sign-on policy evaluation resulted in ENROLL"
| eval timestamp=strftime(_time,"%Y-%m-%d %H:%M:%S")
| eval activatedTime=strftime(activated_time, "%Y-%m-%d %H:%M:%S")
| table timestamp, activated_time, user, src_ip, actor.displayName, email, client_zone, client.userAgent.rawUserAgent, result
| rename timestamp As "Timestamp", activated_time, user As "Username", actor.displayName As "Display Name", email As "Email", client_zone As "Network Zone", client.userAgent.rawUserAgent As "User Agent", result As "Result"
```

## MFA activation
```
index=sso source="Okta:im2" eventType="user.mfa.factor.activate"
| eval timestamp=strftime(_time, "%Y-%m-%d %H:%M:%S")
| table timestamp, user, actor.displayName, src_ip, client.geographicalContext.state, client.device, client.userAgent.rawUserAgent, result
| rename timestamp As "Timestamp", user As "Username", actor.displayName As "Display Name", src_ip As "Source IP", client.geographicalContext.state As "State", client.device As "Device Type", client.userAgent.rawUserAgent As "UserAgent", result As "Result"
```

# Suspicious Activity
```
index="sso" sourcetype="okta:im" eventtype=okta_event_suspicious_activity
| table action.message, action.requestUri, actors{}.displayName, actors{}.id, src_ip, user, targets{}.displayName
```
