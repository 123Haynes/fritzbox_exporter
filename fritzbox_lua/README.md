# Client for LUA API of FRITZ!Box UI

**Note:** This client only support calls that return JSON (some seem to return HTML they are not supported)

There does not seem to be a complete documentation of the API, the authentication and getting a sid (Session ID) is described here:
[https://avm.de/fileadmin/user_upload/Global/Service/Schnittstellen/AVM_Technical_Note_-_Session_ID.pdf]

## Details
Most of the calls seem to be using the data.lua url with a http FORM POST request. As parameters the page and session id are required (e.g.: sid=<SID>&page=engery). The result is JSON with the data needed to create the respective UI.
Some calls (like inetstat_monitor.lua) seem to use GET rather than POST, the client also supports them, but prefix GET: is needed, otherwise a post is done.

Since no public documentation for the JSON format of the various pages seem to exist, you need to observe the calls made by the UI and analyse the JSON result. However the client should be generic enough to get metric and label values from all kind of nested hash and array structures contained in the JSONs.

## Compatibility
The client was developed on a Fritzbox 7590 running on 07.21, other models or versions may behave differently so just test and see what works, but again the generic part of the client should still work as long as there is a JSON result.

## Translations
Since the API is used to drive the UI, labels are translated and will be returned in the language configured in the Fritzbox. There seems to be a lang parameter but it looks like it is simply ignored. Having translated labels is annoying, therefore the clients also support renaming them based on regex.
Currently the regex are defined for:
  - German
  
If your Fritzbox is running in another language you need to adjust them or you will receive different labels, that may not work with dashboards using them for filtering!



