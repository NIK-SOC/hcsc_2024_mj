#!/bin/sh

DIR=$(dirname $(readlink -f $0))

TEMP_DIR=$(mktemp -d)

if [ -f $DIR/../out/challenge.zip ]; then
    rm $DIR/../out/challenge.zip
fi

mkdir $TEMP_DIR/out
mkdir $TEMP_DIR/assets
cp $DIR/../out/prequels_revenge $TEMP_DIR/out
cp $DIR/../out/ynetd $TEMP_DIR/out
cp $DIR/../Dockerfile $TEMP_DIR

cat > $TEMP_DIR/assets/create_message_db.sh <<SCRIPT
#!/bin/sh

sqlite3 messages.db <<SQL
CREATE TABLE messages (name TEXT, message TEXT);
INSERT INTO messages VALUES ('Alice', 'Hello Alice!');
INSERT INTO messages VALUES ('Bob', 'Hello Bob!');
INSERT INTO messages VALUES ('Eve', 'Hello Eve!');
CREATE TABLE flag (flag TEXT);
INSERT INTO flag VALUES ('HCSC24{this_is_a_fake_flag}');
SQL
SCRIPT

cat > $TEMP_DIR/run.sh <<SCRIPT
#!/bin/sh

chmod +x assets/create_message_db.sh
cd assets
./create_message_db.sh
cd ..

docker build -t ctf-prequels-revenge:latest .
docker rm -f ctf-prequels-revenge:latest; docker run --name ctf-prequels-revenge -it --rm -p 3117:3117 -e CHALLENGE_PORT=3117 ctf-prequels-revenge:latest
SCRIPT

cd $TEMP_DIR
zip -r $DIR/../out/challenge.zip .
cd -

rm -r $TEMP_DIR
