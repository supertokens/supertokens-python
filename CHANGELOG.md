# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.0.4] - 2021-10-13
### Added
- Removed the Literal from python 3.8 and added Literal from typing_extensions package. Now supertokens_python can be used with python 3.7 .


## [0.0.3] - 2021-10-13
### Added
- Adds OAuth development keys for Google and Github for faster recipe implementation.

## [0.0.2] - 2021-10-09
### Fixes
- dependency issues for frameworks

## [0.0.1] - 2021-09-10
### Added
- Multiple framework support. Currently supporting Django, Flask(1.x) and Fastapi.
- BaseRequest and BaseResponse interfaces which are used inside recipe instead of previously used Response and Request from Fastapi.
- Middleware, error handlers and verify session for each framework.
- Created a wrapper for async to sync for supporting older version of python web frameworks.
- Base tests for each framework.
- New requirements in the setup file. 
