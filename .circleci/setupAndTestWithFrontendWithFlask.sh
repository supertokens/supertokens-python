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

echo "Testing with frontend website: $2, FREE core: $coreVersion, plugin-interface: $pluginInterfaceVersion"

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
git clone git@github.com:supertokens/supertokens-website.git
cd supertokens-website
git checkout $2
cd ../project/tests/frontendIntegration/flask-server
export PYTHONPATH="${PYTHONPATH}:/root/project" && python3 app.py --port 8080 &
pid=$!
export PYTHONPATH="${PYTHONPATH}:/root/project" && python3 app.py --port 8082 &
pid2=$!
cd ../../../../supertokens-website/test/server
npm i -d --quiet --no-progress
npm i git+https://github.com:supertokens/supertokens-node.git#$3 --quiet --no-progress
cd ../../
npm i -d --quiet --no-progress
SUPERTOKENS_CORE_TAG=$coreTag NODE_PORT=8081 INSTALL_PATH=../supertokens-root npm test
if [[ $? -ne 0 ]]
then
    echo "test failed... killing $pid, $pid2 and exiting!"
    kill -9 $pid
    kill -9 $pid2
    rm -rf ./test/server/node_modules/supertokens-node
    git checkout HEAD -- ./test/server/package.json
    exit 1
fi
echo "all tests passed, killing processes: $pid and $pid2"
kill -9 $pid
kill -9 $pid2
rm -rf ./test/server/node_modules/supertokens-node
git checkout HEAD -- ./test/server/package.json