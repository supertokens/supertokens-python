coreInfo=`curl -s -X GET \
"https://api.supertokens.io/0/core/latest?password=$SUPERTOKENS_API_KEY&planType=FREE&mode=DEV&version=$1" \
-H 'api-version: 0'`
if [[ `echo $coreInfo | jq .tag` == "null" ]]
then
    echo "fetching latest X.Y.Z version for core, X.Y version: $1, planType: FREE gave response: $coreInfo"
    exit 1
fi
coreTag=$(echo $coreInfo | jq .tag | tr -d '"')
coreVersion=$(echo $coreInfo | jq .version | tr -d '"')

pluginInterfaceVersionXY=`curl -s -X GET \
"https://api.supertokens.io/0/core/dependency/plugin-interface/latest?password=$SUPERTOKENS_API_KEY&planType=FREE&mode=DEV&version=$1" \
-H 'api-version: 0'`
if [[ `echo $pluginInterfaceVersionXY | jq .pluginInterface` == "null" ]]
then
    echo "fetching latest X.Y version for plugin-interface, given core X.Y version: $1, planType: FREE gave response: $pluginInterfaceVersionXY"
    exit 1
fi
pluginInterfaceVersionXY=$(echo $pluginInterfaceVersionXY | jq .pluginInterface | tr -d '"')

pluginInterfaceInfo=`curl -s -X GET \
"https://api.supertokens.io/0/plugin-interface/latest?password=$SUPERTOKENS_API_KEY&planType=FREE&mode=DEV&version=$pluginInterfaceVersionXY" \
-H 'api-version: 0'`
if [[ `echo $pluginInterfaceInfo | jq .tag` == "null" ]]
then
    echo "fetching latest X.Y.Z version for plugin-interface, X.Y version: $pluginInterfaceVersionXY, planType: FREE gave response: $pluginInterfaceInfo"
    exit 1
fi
pluginInterfaceTag=$(echo $pluginInterfaceInfo | jq .tag | tr -d '"')
pluginInterfaceVersion=$(echo $pluginInterfaceInfo | jq .version | tr -d '"')

mkdir -p ~/test_report

echo "Testing with frontend auth-react: $2, node tag: $3, FREE core: $coreVersion, plugin-interface: $pluginInterfaceVersion"

cd ../../
git clone git@github.com:supertokens/supertokens-root.git
cd supertokens-root
echo -e "core,$1\nplugin-interface,$pluginInterfaceVersionXY" > modules.txt
./loadModules --ssh
cd supertokens-core
git checkout $coreTag
cd ../supertokens-plugin-interface
git checkout $pluginInterfaceTag
cd ../
echo $SUPERTOKENS_API_KEY > apiPassword
./utils/setupTestEnvLocal
cd ../
git clone git@github.com:supertokens/supertokens-auth-react.git
cd supertokens-auth-react
git checkout $2
npm run init > /dev/null
(cd ./examples/for-tests && npm run link) # this is there because in linux machine, postinstall in npm doesn't work..
cd ./test/server/
npm i git+https://github.com:supertokens/supertokens-node.git#$3  
npm i
cd ../../../project/tests/auth-react/flask-server
export PYTHONPATH="${PYTHONPATH}:/root/project"
python3 app.py --port 8083 &
pid=$!
cd ../../../../supertokens-auth-react/

# When testing with supertokens-auth-react for version >= 0.18 the SKIP_OAUTH 
# flag will not be checked because Auth0 is used as a provider so that the Thirdparty tests can run reliably. 
# In versions lower than 0.18 Github is used as the provider.

# SKIP_OAUTH=true npm run test-with-non-node

mkdir -p ~/test_report/logs
mkdir -p ~/test_report/react-logs
mkdir -p ~/test_report/screenshots

echo "Running tests with React 18"
# Run node server in background.
if [[ "${SERVER_STARTED}" != "true" ]]; then
    (cd test/server/ && TEST_MODE=testing INSTALL_PATH=../../../supertokens-root NODE_PORT=8082 node . >> ~/test_report/react-logs/backend.log 2>&1 &)

    (cd ./examples/for-tests/ && cat | CI=true BROWSER=none PORT=3031 REACT_APP_API_PORT=$apiPort npm run start >> ~/test_report/react-logs/frontend.log 2>&1 &)
fi
# Start front end test app and run tests.

# Wait for the test app to be up before running tests.
while ! curl -s localhost:3031 > /dev/null 2>&1
do
    echo "Waiting for front end test application to start..."
    sleep 5
done

while ! curl -s localhost:8082 > /dev/null 2>&1
do
    echo "Waiting for backend test application to start..."
    sleep 5
done

sleep 2 # Because the server is responding does not mean the app is ready. Let's wait another 2secs to make sure the app is up.


echo "Start mocha testing"

if ! [[ -z "${CI}" ]]; then
    export SPEC_FILES=$(circleci tests glob 'test/end-to-end/**/*.test.js' 'test/unit/**/*.test.js')
    echo "Selected spec files: $SPEC_FILES, $CIRCLE_NODE_TOTAL/$CIRCLE_NODE_INDEX"
fi

SCREENSHOT_ROOT=~/test_report/screenshots APP_SERVER=$apiPort TEST_MODE=testing mocha --bail=$BAIL --require @babel/register --require test/test.mocha.env --timeout 40000 --no-config $SPEC_FILES
testPassed=$?;

if [[ $testPassed -ne 0 ]]
then
    echo "test failed... killing $pid and exiting!"
    kill -9 $pid
    rm -rf ./test/server/node_modules/supertokens-node
    git checkout HEAD -- ./test/server/package.json
    exit 1
fi
echo "all tests passed, killing processes: $pid"
kill -9 $pid
rm -rf ./test/server/node_modules/supertokens-node
git checkout HEAD -- ./test/server/package.json