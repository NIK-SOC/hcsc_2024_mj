#!/bin/sh

DIR=$(dirname $(readlink -f $0))

TEMP_DIR=$(mktemp -d)

if [ -f $DIR/../out/challenge.zip ]; then
    rm $DIR/../out/challenge.zip
fi

mkdir $TEMP_DIR/backend
cp $DIR/../backend/go.mod $TEMP_DIR/backend
cp $DIR/../backend/main.go $TEMP_DIR/backend
cp $DIR/../Dockerfile $TEMP_DIR

cat > $TEMP_DIR/backend/flag.go <<EOF
package main

const flag = "flag{this_is_a_fake_flag}"
const flagText = "Congratulations on solving the challenge! If you solve this challenge on the remote host, you get some extra information instead of this placeholder. But here is your flag: " + flag
EOF

cat > $TEMP_DIR/run.sh <<EOF
#!/bin/sh
docker build -t ctf-epiclitl_curve:latest .
docker run -it --rm --name ctf-epiclitl_curve -p 1337:1337 -e BACKEND_PORT=1337 ctf-epiclitl_curve:latest
EOF

chmod +x $TEMP_DIR/run.sh

if [ ! -d $DIR/../out ]; then
    mkdir $DIR/../out
fi

cd $TEMP_DIR
zip -r $DIR/../out/challenge.zip .
cd -

rm -r $TEMP_DIR
