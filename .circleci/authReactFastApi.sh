echo "Starting tests for FDI $1";

if [ -z "$SUPERTOKENS_API_KEY" ]; then
    echo "SUPERTOKENS_API_KEY not set"
    exit 1
fi
frontendDriverVersion=$1
frontendDriverVersion=`echo $frontendDriverVersion | tr -d '"'`
if [[ $frontendDriverVersion == '1.0' ]]; then
    mkdir ../../supertokens-auth-react
    mkdir ../../supertokens-auth-react/test_report
    exit 0
fi

coreDriverJson=`cat ../coreDriverInterfaceSupported.json`
coreDriverLength=`echo $coreDriverJson | jq ".versions | length"`
coreDriverArray=`echo $coreDriverJson | jq ".versions"`
coreDriverVersion=`echo $coreDriverArray | jq ". | last"`
coreDriverVersion=`echo $coreDriverVersion | tr -d '"'`
coreFree=`curl -s -X GET \
"https://api.supertokens.io/0/core-driver-interface/dependency/core/latest?password=$SUPERTOKENS_API_KEY&planType=FREE&mode=DEV&version=$coreDriverVersion" \
-H 'api-version: 0'`
if [[ `echo $coreFree | jq .core` == "null" ]]
then
    echo "fetching latest X.Y version for core given core-driver-interface X.Y version: $coreDriverVersion, planType: FREE gave response: $coreFree. Please make sure all relevant cores have been pushed."
    exit 1
fi
coreFree=$(echo $coreFree | jq .core | tr -d '"')


frontendVersionXY=`curl -s -X GET \
"https://api.supertokens.io/0/frontend-driver-interface/dependency/frontend/latest?password=$SUPERTOKENS_API_KEY&frontendName=website&mode=DEV&version=$frontendDriverVersion" \
-H 'api-version: 0'`
if [[ `echo $frontendVersionXY | jq .frontend` == "null" ]]
then
    echo "fetching latest X.Y version for frontend given frontend-driver-interface X.Y version: $frontendDriverVersion, name: webiste gave response: $frontend. Please make sure all relevant versions have been pushed."
    exit 1
fi
frontendVersionXY=$(echo $frontendVersionXY | jq .frontend | tr -d '"')

frontendInfo=`curl -s -X GET \
"https://api.supertokens.io/0/driver/latest?password=$SUPERTOKENS_API_KEY&mode=DEV&version=$frontendVersionXY&name=website" \
-H 'api-version: 0'`
if [[ `echo $frontendInfo | jq .tag` == "null" ]]
then
    echo "fetching latest X.Y.Z version for frontend, X.Y version: $frontendVersionXY gave response: $frontendInfo"
    exit 1
fi
frontendTag=$(echo $frontendInfo | jq .tag | tr -d '"')
frontendVersion=$(echo $frontendInfo | jq .version | tr -d '"')

nodeVersionXY=`curl -s -X GET \
"https://api.supertokens.io/0/frontend-driver-interface/dependency/driver/latest?password=$SUPERTOKENS_API_KEY&mode=DEV&version=$frontendDriverVersion&driverName=node" \
-H 'api-version: 0'`
if [[ `echo $nodeVersionXY | jq .driver` == "null" ]]
then
    echo "fetching latest X.Y version for driver given frontend-driver-interface X.Y version: $frontendDriverVersion gave response: $nodeVersionXY. Please make sure all relevant drivers have been pushed."
    exit 1
fi
nodeVersionXY=$(echo $nodeVersionXY | jq .driver | tr -d '"')

nodeInfo=`curl -s -X GET \
"https://api.supertokens.io/0/driver/latest?password=$SUPERTOKENS_API_KEY&mode=DEV&version=$nodeVersionXY&name=node" \
-H 'api-version: 0'`
if [[ `echo $nodeInfo | jq .tag` == "null" ]]
then
    echo "fetching latest X.Y.Z version for driver, X.Y version: $nodeVersionXY gave response: $nodeInfo"
    exit 1
fi
nodeTag=$(echo $nodeInfo | jq .tag | tr -d '"')

frontendAuthReactVersionXY=`curl -s -X GET \
"https://api.supertokens.io/0/frontend-driver-interface/dependency/frontend/latest?password=$SUPERTOKENS_API_KEY&frontendName=auth-react&mode=DEV&version=$frontendDriverVersion" \
-H 'api-version: 0'`
if [[ `echo $frontendAuthReactVersionXY | jq .frontend` == "null" ]]
then
    echo "fetching latest X.Y version for frontend given frontend-driver-interface X.Y version: $frontendDriverVersion, name: auth-react gave response: $frontend. Please make sure all relevant frontend libs have been pushed."
    exit 1
fi
frontendAuthReactVersionXY=$(echo $frontendAuthReactVersionXY | jq .frontend | tr -d '"')

frontendAuthReactInfo=`curl -s -X GET \
"https://api.supertokens.io/0/driver/latest?password=$SUPERTOKENS_API_KEY&mode=DEV&version=$frontendAuthReactVersionXY&name=auth-react" \
-H 'api-version: 0'`
if [[ `echo $frontendAuthReactInfo | jq .tag` == "null" ]]
then
    echo "fetching latest X.Y.Z version for frontend, X.Y version: $frontendAuthReactVersionXY gave response: $frontendAuthReactInfo"
    exit 1
fi
frontendAuthReactTag=$(echo $frontendAuthReactInfo | jq .tag | tr -d '"')
frontendAuthReactVersion=$(echo $frontendAuthReactInfo | jq .version | tr -d '"')

if [[ $frontendDriverVersion == '1.3' || $frontendDriverVersion == '1.8' ]]; then
    # we skip this since the tests for auth-react here are not reliable due to race conditions...

    # we skip 1.8 since the SDK with just 1.8 doesn't have the right scripts
    mkdir ../../supertokens-auth-react
    mkdir ../../supertokens-auth-react/test_report
    exit 0
else
    tries=1
    while [ $tries -le 3 ]
    do
        tries=$(( $tries + 1 ))
        ./setupAndTestWithAuthReact.sh $coreFree $frontendAuthReactTag $nodeTag
        if [[ $? -ne 0 ]]
        then
            if [[ $tries -le 3 ]]
            then
                rm -rf ../../supertokens-root
                rm -rf ../../supertokens-auth-react
                echo "failed test.. retrying!"
            else
                echo "test failed for auth-react tests... exiting!"
                exit 1
            fi
        else
            rm -rf ../../supertokens-root
            # we do not delete supertokens-auth-react here cause the test reports are generated in there.
            break
        fi
    done
fi