rm -R dokka/
java -jar hw-security/libs/dokka-hugo-fatjar-0.9.17.jar hwsecurity/src/main/java/ -output dokka/reference/ -format hugo
