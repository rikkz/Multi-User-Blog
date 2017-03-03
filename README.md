# Multi-User-Blog

<h2>Introduction</h2>
<p>This is a web page being hosted on Google App Engine where users can sign in and post blog posts as well as 'Like' and 'Comment' on other posts made on the blog.</p>
<a href="http://blogstar-159204.appspot.com"> Multi User Blog </a>
<h2> Instructions </h2>
<ul type="disc">
  <li><b>Setup</b></li>
  <ul type="disc">
    <li><a href="https://www.python.org/downloads/">Install Python</a> if necessary.</li>
    <li><a href="https://cloud.google.com/appengine/downloads#Google_App_Engine_SDK_for_Python">Install Google App Engine.</a></li>
    <li><a href="https://console.cloud.google.com/appengine/?pli=1">Sign Up for a Google App Engine Account.</a></li>
    <li><a href="https://console.cloud.google.com/">Create a new project in Google’s Developer Console using a unique name.</a></li>
    <li><a href="https://cloud.google.com/sdk/docs/">Install gcould tool.</a></li>
  </ul>
  <li><b>Download the Multi User Blog app</b></li>
  <ul type="disc">
    <li>Clone the Multi User Blog app repository to your local machine:
      <pre>git clone https://github.com/rikkz/Multi-User-Blog</pre>
    </li>
    <li> Open terminal and go to the project folder.</li>
  </ul>
  <li><b>Test the application</b></li>
  <ul type="disc">
    <li> From within the project directory, start the local development server with the following command: 
      <pre> dev_appserver.py app.yaml </pre>
      <p>The local development server is now running and listening for requests on port 16081.</p>
    </li>
    <li> Visit http://localhost:16081/blog in your web browser to view the app. </li>
  </ul>
