### Inventory Tracker Snowflake API
This software is a simple AWS Lambda API that acts as the middleware between the Android app and the Snowflake database.<br>
It handles HTTP requests and creates prepared statements out of body information, returning the result of the prepared statements.<br>
All data is sent in the body of the HTTP request for added security.<br>
Passwords are hashed using SHA-256 and they are stored and retrieved as such for security purposes.<br>
<br>
This project is based on the Apache licensed example code by Snowflake: https://www.snowflake.com/en/developers/guides/build-a-custom-api-in-java-on-aws/<br>
Significant edits and improvements are made where needed to achieve the end goal.
