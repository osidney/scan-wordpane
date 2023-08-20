#!/usr/bin/env bash

#################################### SCAN WORDPANE #########################################
#     Este script ajuda a limpar sites WordPress infectados, substitui núcleo/plugin/tema  #
#     arquivos e encontrar código mal-intencionado que foi injetado no site.               #
#     Desenvolvido por Sidney Andrews.                                                     #
#     Suporte: Consulte a documentação da WordPane.                                        # 
#########################################################################################

#################################### Requisitos ################################################
#Verificando se todos os pré-requisitos estão presentes para habilitar a funcionalidade completa.#
##################################################################################################
if ! hash awk 2>/dev/null
then
    echo "'awk' is not available for use."
    exit 1
elif ! hash cut 2>/dev/null
then
    echo "'cut' is not available for use."
    exit 1
elif ! hash egrep 2>/dev/null
then
    echo "'egrep' is not available for use."
    exit 1
elif ! hash find 2>/dev/null
then
    echo "'find' is not available for use."
    exit 1
elif ! hash grep 2>/dev/null
then
    echo "'grep' is not available for use."
    exit 1
elif ! hash printf 2>/dev/null
then
    echo "'printf' is not available for use."
    exit 1
elif ! hash uniq 2>/dev/null
then
    echo "'uniq' is not available for use."
    exit 1
elif ! hash xargs 2>/dev/null
then
    echo "'xargs' is not available for use."
    exit 1
else
    #all good, clear the screen
    clear
fi

###################################### Global ###########################################
#     Definindo variáveis ​​globais e funções usadas em todo o script.                    #
#########################################################################################

### Diretório base ###
# Usado para garantir que o script possa retornar à pasta "home"
workingdirectory=$(pwd)

### Data e hora ###
# Destinado a carimbar a data e hora no arquivo de log
datetime=$(date +%Y-%m-%d.%H:%M:%S)

### Core version ###
version=$(grep wp_version wp-includes/version.php | egrep -o "([0-9]{1,}\.)+[0-9]{1,}")

### Backup ###
# Declare a variável "backup" e defina seu valor como 0.
declare -i backup=0

### Display the logo ###
function display_logo {
    echo " __          __           _ _____                  "
    echo " \ \        / /          | |  __ \                 "
    echo "  \ \  /\  / /__  _ __ __| | |__) |_ _ _ __   ___  "
    echo "   \ \/  \/ / _ \|  __/ _  |  ___/ _  |  _ \ / _ \ "
    echo "    \  /\  / (_) | | | (_| | |  | (_| | | | |  __/ "
    echo "     \/  \/ \___/|_|  \__,_|_|   \__,_|_| |_|\___| "
    echo "                                                   "
    echo "               Soluções Cloud WordPress            "
    echo "                                                   "
    echo "                                                   "
    echo "                                       wordpane.com"
    echo "                                       Versão 1.0  "
    echo "                                                   "
}

###################################### Globals ##########################################
#             Declarar funcionalidades usadas em várias funções                         #
#########################################################################################
function initialize_logfile {
    display_logo >> $workingdirectory/scan-wordpane-$datetime.log
}

################################ Definições de Malware ###################################
#          Assinaturas de malware para detecção de arquivos maliciosos ou suspeitos     #
#########################################################################################
function general_remove_onboarding_form_jpg {
    # Removes Malware.Expert.generic.eval.gzinflate.strrot13.base64.1
    echo "onboarding_form_jpg"
    find . -type f -name onboarding_form.jpg | xargs grep -F 'LUrXEqu4tvyaqTP3DVmu81HOOZqXRnEwOYevv2/PuHkshKQlpF7draUZ7r+3/lXWe6iWv8ehXGP0f/MypfPyajH86uL' | cut -d ":" -f1 | uniq | xargs rm -rfv >> $workingdirectory/arquivos-infectados.log
}

function general_remove_win_trojan_hide_1 {
    # Removes Win.Trojan.Hide-1
    echo "win_trojan_hide_1"
    find . -type f \( -name "*.gif" -or -name "*.jpg" -or -name "*.jpeg" -or -name "*.php" \) | xargs grep -F 'GIF89a' | cut -d ":" -f1 | uniq | xargs rm -rfv >> $workingdirectory/arquivos-infectados.log
}

function general_remove_inputfiles {
    echo "general_remove_inputfiles"
    general_inputfiles=$(find | grep -lP "./_input_\d_.[[:alnum:]]+")
    printf "%s\n" "$general_inputfiles" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_ico {
    echo "general_remove_ico"
    remove_icofiles=$(find . -name ".*.ico")
    printf "%s\n" "$remove_icofiles" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_suspected {
    echo "general_remove_suspected"
    remove_suspectedfiles=$(find . -name "*.suspected")
    printf "%s\n" "$remove_suspectedfiles" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_joomla_malware_1 {
    # Finds Malware.Expert.generic.joomla.malware.1 infections
    echo "generic_joomla_malware_1"
    generic_joomla_malware_1files=$(find . -type f \( -name "cjsxf.php" -or -name "gyovh.php" -or -name "dbpqz.php" -or -name "_input_1_test.php*"  \))
    printf "%s\n" "$generic_joomla_malware_1files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_eval_base64_post_3 {
    # Finds Malware.Expert.Generic.Eval.Base64.Post.3
    echo "generic_eval_base64_post_3"
    generic_eval_base64_post_3files=$(find . -iname '*.php' -exec grep -lP '\<\?php\s\/\*457563643\*\/\serror_reporting\(0\)' {} \;)
    printf "%s\n" "$generic_eval_base64_post_3files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_base64_decode_21 {
    # Finds Malware.Expert.generic.base64.decode.21
    echo "generic_base64_decode_21"
    generic_base64_decode_21files=$(find . -iname '*.php' -exec grep -lP '\$xpg5l1\=\"8esJBn\+qkWeSSHuWdYtPTS2K2' {} \;)
    printf "%s\n" "$generic_base64_decode_21files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_php_uploader_max_706 {
    # Finds php.uploader.max.706
    echo "php_uploader_max_706"
    php_uploader_max_706files=$(find . -iname '*.php' -exec grep -lP "\{\sif\(\@copy\(\\\$\_FILES\['file\'\]\[\'tmp\_name\'\]\,\s\\\$\_FILES\[\'file\'\]\[\'name\'\]\)\)\s\{\secho\s\'\<b\>Upload\sSuccess\s\!\!\!\<\/b\>\<\<\/script\>\<br\>\<br\>\'\;\s\}\selse\s\{\secho\s\'\<b\>Upload\sFail\s\!\!\!\<\/b\>\<br\>\<br\>\'\;\s\}\}" {} \;)
    printf "%s\n" "$php_uploader_max_706files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_create_function_10 {
    # Finds Malware.Expert.generic.create.function.10
    echo "generic_create_function_10"
    generic_create_function_10files=$(find . -type f -name "*.php" -or -name "*.suspected" -exec grep -lP "for\s\(\\\$[a-zA-Z0-9_]+\s\=\s0\;\s\\\$[a-zA-Z0-9_]+\s\<\sstrlen\(\\\$[a-zA-Z0-9_]+\)\s\&\&\s\\\$[a-zA-Z0-9_]+\s\<\sstrlen\(\\\$[a-zA-Z0-9_]+\)\;\s\\\$[a-zA-Z0-9_]+\+\+\,\s\\\$[a-zA-Z0-9_]+\+\+\)" {} \;)
    printf "%s\n" "$generic_create_function_10files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_eval_82 {
    # Finds Malware.Expert.generic.eval.82 infections
    echo "generic_eval_82"
    generic_eval_82files=$(find . -type f -name ".*.ico" -exec grep -lP "\\\$[a-zA-Z0-9_]+\s\=\sbasename\/[a-zA-Z0-9_*]+\/\(\/[a-zA-Z0-9_*]+\/trim\/[a-zA-Z0-9_*]+\/\(\/[a-zA-Z0-9_*]+\/preg_replace\/[a-zA-Z0-9_*]+\/\(\/[a-zA-Z0-9_*]+\/rawurldecode\/[a-zA-Z0-9_*]+\/\(\/[a-zA-Z0-9_*]+\/" {} \;)
    printf "%s\n" "$generic_eval_82files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_eval_gzinflate_base64_15 {
    # Finds Malware.Expert.generic.eval.gzinflate.base64.15 infections
    echo "generic_eval_gzinflate_base64_15"
    generic_eval_gzinflate_base64_15files=$(find . -type f -exec grep -lP 'eval\(\"\\n\\\$dgreusdi\s\=\sintval\(\_\_LINE\_\_\)\s\*\s337\;\"\)\;' {} \;)
    printf "%s\n" "$generic_eval_gzinflate_base64_15files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_fwrite_htaccess_4 {
    # Finds Malware.Expert.generic.fwrite.htaccess.4 infections
    echo "generic_fwrite_htaccess_4"
    generic_fwrite_htaccess_4files=$(find . -type f \( -name "*.php" -or -name "*.zip" \) -exec grep -lP 'curl\_setopt\(\$ch\,\sCURLOPT\_URL\,\s\"http\:\/\/snijorsz\.pw\/story2\.php\?q\=\$query\_pars\_2\&pass\=qwerty8\"\)\;' {} \;)
    printf "%s\n" "$generic_fwrite_htaccess_4files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_webShellOrb_web_shell_0 {
    # Removes Malware.Expert.WebShellOrb.web.shell.0 infections
    echo "webShellOrb_web_shell_0"
    webShellOrb_web_shell_0files=$(find . -type f -name "*.php" -exec grep -lP '\\\$[a-zA-Z0-9]+\=file\(\_\_FILE\_\_\)\;eval\(base64\_decode\(\"[a-zA-Z0-9]+\"\)\)\;eval\(base64\_decode\([a-zA-Z0-9]+\(\\\$[a-zA-Z0-9]+\)\)\)\;' {} \;)
    printf "%s\n" "$webShellOrb_web_shell_0files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_b374k_shell_3 {
    # Finds Malware.Expert.b374k.shell.3 infections
    echo "b374k_shell_3"
    b374k_shell_3files=$(find . -type f -exec grep -lP '\\\$s\_func\=\"cr\"\.\"eat\"\.\"e\_fun\"\.\"cti\"\.\"on\"\;\$b374k\=\@\\\$s\_func\(' {} \;)
    printf "%s\n" "$b374k_shell_3files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_malware_124 {
    # Finds Malware.Expert.generic.malware.124 infections
    echo "generic_malware_124"
    generic_malware_124files=$(find . -type f -name "*.php" -exec grep -lP '\<\?php\s\\\$\{\"\\x47L\\x4fBALS\"\}\[\"\\x6egajuf\\x66\"\]\=\"\\x6d\"\;\\\$\{\"\\x47\\x4cO\\x42A\\x4c\\x53\"\}' {} \;)
    printf "%s\n" "$generic_malware_124files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_malware_172 {
    # Finds Malware.Expert.generic.malware.172 infections
    echo "generic_malware_172"
    generic_malware_172files=$(find . -type f -exec grep -lP '(\\\$q[0-9\s\=\s\"[O0]+\"\;){15}' {} \;)
    printf "%s\n" "$generic_malware_172files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_php_shell_black_id_700 {
    # Finds PHP.Shell.Black.Id.700 infections
    echo "php_shell_black_id_700"
    php_shell_black_id_700files=$(find . -type f -name "*.php" -exec grep -lP '\,\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6C\\x61\\x74\\x65\\x28\\x62\\x61' {} \;)
    printf "%s\n" "$php_shell_black_id_700files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_php_base64_v23au_187 {
    # Finds PHP.Base64.V23au.187 Variant A infections
    echo "php_base64_v23au_187"
    php_base64_v23au_187files=$(find . -type f \( -name "*.php" -or -name "*.ico" \) -exec grep -lP "\\\$[a-z]+\s\=\s[0-9]+\;\sfunction\s[a-z]+\(\\\$[a-z]+\,\s\\\$[a-z]+\)\{\\\$[a-z]+\s\=\s\'\'\;\sfor\(\\\$i\=0\;\s\\\$i\s\<\sstrlen\(\\\$[a-z]+\)\;\s\\\$i\+\+\)" {} \;)
    printf "%s\n" "$php_base64_v23au_187files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_eval_79 {
    # Finds Malware.Expert.Generic.Eval.79 infections
    echo "generic_eval_79"
    generic_eval_79files=$(find . -type f -name "*.php" -exec grep -lP "\<\?php\s\\\$[a-z0-9]+\s\=\s[0-9]+\;\\\$GLOBALS\[\'[a-z0-9]+\'\]\s\=\sArray\(\)\;global\s\\\$[a-z0-9]+\;\\\$[a-z0-9]+\s\=\s\\\$GLOBALS\;\\\$\{" {} \;)
    printf "%s\n" "$generic_eval_79files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_malware_135 {
    # Finds Malware.Expert.Generic.Malware.135 infections
    echo "generic_malware_135"
    generic_malware_135files=$(find . -type f -name "*.php" -exec grep -lP '\<\?php\s\\\$[a-z]+\s\=\s\"[a-z]+\"\;\\\$[a-z]+\s\=\s\"\"\;foreach\s\(\\\$\_POST\sas\s\\\$[a-z]+\s\=\>\s\\\$[a-z]+\)\{if\s\(strlen\(\\\$[a-z]+\)\s\=\=\s16\sand\ssubstr\_count\(\\\$[a-z]+\,\s\"\%\"\)\s\>\s10\)' {} \;)
    printf "%s\n" "$generic_malware_135files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_eval_27 {
    # Finds Malware.Expert.Generic.Eval.27 infections
    echo "generic_eval_27"
    generic_eval_27files=$(find . -type f -name "*.php" -exec grep -lP '\<\?php\serror\_reporting\(0\)\;\\\$\_[a-zA-Z0-9]+\=\"[a-zA-Z0-9]+\"\;\\\$\_[a-zA-Z0-9]+\=array\([0-9,]+\)\;\$payload\=\"([a-zA-Z0-9+]+\/){25}' {} \; )
    printf "%s\n" "$generic_eval_27files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_uploader_6 {
    # Finds Malware.Expert.Generic.Uploader.6 infections
    echo "generic_uploader_6"
    generic_uploader_6files=$(find . -type f -name "info.php" -exec grep -lP '\\\$write\s\=\sfwrite\s\(\\\$file\s\,base64\_decode\(\\\$azx\)\)\;' {} \;)
    printf "%s\n" "$generic_uploader_6files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_malware_136 {
    # Finds Malware.Expert.Generic.Malware.136 infections
    echo "generic_malware_136"
    generic_malware_136files=$(find . -type f -name "*.php" -exec grep -lP 'if\(\!function\_exists\(\"TC9A16C47DA8EEE87\"\)\)\{function\sTC9A16C47DA8EEE87\(\\\$T059EC46CFE335260\)\{\\\$T059EC46CFE335260\=base64\_decode\(\\\$T059EC46CFE335260\)\;' {} \;)
    printf "%s\n" "$generic_malware_136files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_dropsforums_ru_bruteforce_1 {
    # Finds Dropforums.Ru.Bruteforce.1 infections
    echo "dropsforums_ru_bruteforce_1"
    dropsforums_ru_bruteforce_1files=$(find . -type f -name "info.php" -exec grep -lP "\\\$server\_url\s\=\s\'http\:\/\/dropsforums\.ru\/panel[a-zA-Z_/]+\.php\'\;" {} \;)
    printf "%s\n" "$dropsforums_ru_bruteforce_1files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_encoded_zip_file_0 {
    # Removes Malware.Expert.Generic.Encoded.Zip.File.0 infections
    echo "generic_encoded_zip_file_0"
    generic_encoded_zip_file_0files=$(find . -type f -name "*.php" -exec grep -lP 'base64\_decode\(\"UEsDBAoAAAAAAMio204AAAAAAAAAAAAAAAAGAAAAcm9hd2svUEsDBAoAAAAAAKS02U' {} \;)
    printf "%s\n" "$generic_encoded_zip_file_0files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_eval_base64_decode_14 {
    # Finds Malware.Expert.Generic.Eval.Base64.Decode.14A infections
    echo "generic_eval_base64_decode_14A"
    generic_eval_base64_decode_14Afiles=$(find . -type f -name "*.php" -exec grep -lP 'base64\_decode\(\"PD9waHANCmhlYWRlcignQ29udGVudC1UeXBlOnRleHQvaHRtbDsgY2hhcnNldD1VVEYtOCcpOw0KDQpAc2V0X3Rp' {} \;)
    printf "%s\n" "$generic_eval_base64_decode_14Afiles" >> $workingdirectory/arquivos-infectados.log
    # Finds Malware.Expert.Generic.Eval.Base64.Decode.14B infections
    echo "generic_eval_base64_decode_14B"
    generic_eval_base64_decode_14Bfiles=$(find . -type f -name "*.php" -exec grep -lP "\\\$[a-z]+\_code\s\=\s\'PD9waHANCmhlYWRlcignQ29udGVudC1UeXBlOnRleHQvaHRtbDsgY2hhcnNldD1VVEYtOCcpOw0K" {} \;)
    printf "%s\n" "$generic_eval_base64_decode_14Bfiles" >> $workingdirectory/arquivos-infectados.log
    # Finds Malware.Expert.Generic.Eval.Base64.Decode.14C infections
    echo "generic_eval_base64_decode_14C"
    generic_eval_base64_decode_14Cfiles=$(find . -type f -name "*.php" -exec grep -lP 'base64\_decode\(\"Z2lmODlhPD9waHAgQGV2YWwoJF[a-zA-Z0-9+/]+\=\"\)\)\;\s\?\>' {} \;)
    printf "%s\n" "$generic_eval_base64_decode_14Cfiles" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_leaf_mailer_0 {
    # Finds Malware.Expert.Leaf.Mailer.0 infections
    echo "leaf_mailer_0"
    leaf_mailer_0files=$(find . -type f -name "*.php" -exec grep -lP '\*\sLeaf\sPHP\sMailer\sby\s\[leafmailer\.pw\]' {} \;)
    printf "%s\n" "$leaf_mailer_0files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_php_print_md5_0 {
    # Finds Malware.Expert.Php.Print.Md5.0 infections
    echo "php_print_md5_0"
    php_print_md5_0files=$(find . -type f -exec grep -lP 'php\%20print\(md5\(222\)\)\;\$a\=str\_replace\(\%22vbnm\%22\,\%22\%22\,\%22asvbnmsert\%22\)' {} \;)
    printf "%s\n" "$php_print_md5_0files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_eval_post_0 {
    # Finds Malware.Expert.Generic.Eval.Post.0 infections
    echo "generic_eval_post_0"
    generic_eval_post_0files=$(find . -type f -name "vuln.php" -exec grep -lP 'Vuln\!\!\<\?php\s\@eval\(\$\_POST\[pass\]\)\s\?\>' {} \;)
    printf "%s\n" "$generic_eval_post_0files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_malware_178 {
    # Finds Malware.Expert.Generic.Malware.178 Variant A infections
    echo "generic_malware_178"
    generic_malware_178files=$(find . -type f -exec grep -lP "(\\\$[a-zA-Z0-9]+\[[0-9]+\]\.){10,}" {} \;)
    printf "%s\n" "$generic_malware_178files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_eval_base64_decode_24 {
    # Finds Malware.Expert.Generic.Eval.Base64.Decode.24 infections
    echo "generic_eval_base64_decode_24"
    generic_eval_base64_decode_24files=$(find . -type f -name "*.php" -exec grep -lP 'PD9waHAK[a-zA-Z0-9]+' {} \;)
    printf "%s\n" "$generic_eval_base64_decode_24files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_wordpress_file_put_contents_1 {
    # Finds Malware.Expert.WordPress.File.Put.Contents.1 infections
    echo "wordpress_file_put_contents_1"
    wordpress_file_put_contents_1files=$(find . -type f -name "*.php" -exec grep -lP 'PD9waHAK[a-zA-Z0-9]+' {} \;)
    printf "%s\n" "$wordpress_file_put_contents_1files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_malware_98 {
    # Finds Malware.Expert.Generic.Malware.98 infections
    echo "generic_malware_98"
    generic_malware_98files=$(find . -type f \( -name "wp-blogs.php" -or -name "license" -or -name "index.php" \) -exec grep -lP '([b6-9])+\"\)\;foreach\(\$([b6-9])+\sas\\\$([b6-9])+\=\>\\\$([b6-9])+\)' {} \;)
    printf "%s\n" "$generic_malware_98files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_malware_158 {
    # Finds Malware.Expert.Generic.Malware.158 infections
    echo "generic_malware_158"
    generic_malware_158files=$(find . -type f -name "*.php" -exec grep -lP '\{function\sstr\_ireplace\(\$from,\$to\,\\\$string\)\{return\strim\(preg\_replace\(\"\/\"\.addcslashes\(\$from\,\"\?\:\\\\\/\*\^\$\"\)\.\"\/si\"' {} \;)
    printf "%s\n" "$generic_malware_158files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_malware_189 {
    # Finds Malware.Expert.Generic.Malware.189 infections
    echo "generic_malware_189"
    generic_malware_189files=$(find . -type f -name "eval-81809123.php")
    printf "%s\n" "$generic_malware_189files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_php_malware_magento_594 {
    # Finds PHP.Malware.Magento.594 infections
    echo "php_malware_magento_594"
    php_malware_magento_594files=$(find . -type f -exec grep -lP "\\\$post\=\'[a-z=_&]+\'\.urlencode\(\\\$eval\_sub\)\.\'[a-zA-F0-9=_&.%]+\'\.urlencode\(base64\_encode\(\\\$code\)\)\;" {} \;)
    printf "%s\n" "$php_malware_magento_594files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_php_nested_base64_641 {
    # Finds PHP.Nested.Base64.641 infections
    echo "php_nested_base64_641"
    php_nested_base64_641files=$(find . -type f \( -name "agger.*.j" -or -name "magic.*.j" \) -exec grep -lP "eval\(gzinflate\(str\_rot13\(base64\_decode\(\'[a-zA-Z0-9/+=]+\'\)\)\)\)\;\s\?\>" {} \;)
    printf "%s\n" "$php_nested_base64_641files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_malware_165 {
    # Finds Malware.Expert.Generic.Malware.165 infections
    echo "generic_malware_165"
    generic_malware_165files=$(find . -type f -name "*.php" -exec grep -lP "[pP]reman[kK]eyboard" {} \;)
    printf "%s\n" "$generic_malware_165files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_steal_user_pass_2 {
    # Finds Malware.Expert.Steal.User.Pass.2 infections
    echo "generic_steal_user_pass_2"
    generic_steal_user_pass_2files=$(find . -type f -name "index.php" -exec grep -lP '\(\"Location\:\shttps\:\/\/aromasnadal.com\/bl\"\)\;' {} \;)
    printf "%s\n" "$generic_steal_user_pass_2files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_php_cmdshell_cih_233 {
    # Finds PHP CmdShell CIH 233 infections
    echo "generic_php_cmdshell_cih_233"
    generic_php_cmdshell_cih_233files=$(find . -type f -name "*.php" -exec grep -lP 'R0lGODlhJgAWAIAAAAAAAP\/\/\/yH5BAUUAAEALAAAAAAmABYAAAIvjI\+py\+0PF4i0gVvzuVxXDnoQ' {} \;)
    printf "%s\n" "$generic_php_cmdshell_cih_233files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_php_cmdshell_egyspider_240 {
    # Finds WebShellOrb.Web.Shell.0 infections
    echo "php_cmdshell_egyspider_240"
    php_cmdshell_egyspider_240files=$(find . -type f -name "*.php" -exec grep -lP '\\\$back\_connect\_c\=\"I2luY2x1ZGUgPHN0ZGlvLmg\+[a-zA-Z0-9]+\"\;' {} \;)
    printf "%s\n" "$php_cmdshell_egyspider_240files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_php_cmdshell_generic_276 {
    # Finds Php.Cmdshell.generic.276 infections
    echo "php_cmdshell_generic_276"
    php_cmdshell_generic_276files=$(find . -type f -name "*.php" -exec grep -lP "\/\*\s\(1n73ction\sshell\sv3\.3\sby\sx\'1n73ct\s\|\sdefault\spass\:" {} \; )
    printf "%s\n" "$php_cmdshell_generic_276files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_cmb_base64decode_hex {
    # Finds CMB.Base64decode.Hex infections
    echo "cmb_base64decode_hex"
    cmb_base64decode_hexfiles=$(find . -type f -name "*.php" -exec grep -lP 'Configuration\:\:get\(\"(\\[x0-9a-f]+){21}\"\)\;\sgoto\s[A-Za-z0-9]+\;' {} \;)
    printf "%s\n" "$cmb_base64decode_hexfiles" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_malware_155 {
    # Finds Malware.Expert.Generic.Malware.155 infections
    echo "generic_malware_155"
    generic_malware_155files=$(find . -type f -name "*.php" -exec grep -lP "\<\?php\s\\\$GLOBALS\[\'\_[0-9]+\_\'\]\=Array\(\'str\_\'\s\.\'rot13\'\,\'pack\'\,\'st\'\s\.\'rrev\'\)\;\s\?\>\<\?php\sfunction\s\_[0-9]+\(\\\$i\)\{\\\$a\=Array\(" {} \;)
    printf "%s\n" "$generic_malware_155files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_malware_41 {
    # Finds Malware.Expert.Generic.Malware.41 infections
    echo "generic_malware_41"
    generic_malware_41files=$(find . -type f -exec grep -lP '(\$arr\_word\[[0-9]+\]\[\]\s\=\"[0-9]\"\;){120}' {} \;)
    printf "%s\n" "$generic_malware_41files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_uploader_4 {
    # Finds Malware.Expert.Generic.Uploader.4 infections
    echo "generic_uploader_4"
    generic_uploader_4files=$(find . -type f -name "*.php" -exec grep -lP '<\?php\sif\s\(isset\(\\\$\_GET\[\"CONFIG\"\]\)\)\sif\s\(\"02a2e55e48c352aec1c6543581533d38\"\s\=\=\smd5\(\$\_GET\[\"CONFIG\"\]\)\)\{echo\s\"\<form\smethod\=\\\"post\\\"\senctype\=\\\"multipart\/form\-data\\\"\>' {} \;)
    printf "%s\n" "$generic_uploader_4files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_eval_post_8 {
    # Finds Malware.Expert.Generic.Eval.Post.8 infections
    echo "generic_eval_post_8"
    generic_eval_post_8files=$(find . -type f -name "*.php" -exec grep -lP "gif89a\<\?php\s\@eval\(\\\$\_POST\[\'pass\'\]\)\;\?\>" {} \;)
    printf "%s\n" "$generic_eval_post_8files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_filebox_1 {
    # Finds Malware.Expert.Filebox.1 infections
    echo "filebox_1"
    filebox_1files=$(find . -type f -name "*.php" -exec grep -lP "\{if\(\!\@ereg\(\\\$c\,\\\$j\)\)\{\\\$j\=\$c\;\}\}\\\$l\=\\\$j\;if\(\@\\\$\_COOKIE\[\'pass\'\]\!\=md5\(\\\$f\)\)\{if\(\@\\\$\_REQUEST\[\'pass\'\]\=\=\\\$f\)\{setcookie\(\'pass\'\,md5\(\\\$f\)\,time\(\)\+60\*60\*24\*1\)\;\}else\{if\(\@\\\$\_REQUEST\[\'pass\'\]\)\\\$m\=true\;login\(\@\\\$m\)\;\}\}function\smaintop\(\\\$n\,\\\$o\=true\)" {} \;)
    printf "%s\n" "$filebox_1files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_malware_444 {
    # Finds Malware.Expert.generic.malware.444 infections
    echo "generic_malware_444"
    generic_malware_444files=$(find . -type f -name "*.php" -exec grep -lP "(\\\$GLOBALS\[\'[a-zA-Z0-9]+\'\]\[[0-9]+]\.){15}" {} \;)
    printf "%s\n" "$generic_malware_444files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_eval_9 {
    # Finds Malware.Expert.Generic.Eval.9 infections
    echo "generic_eval_9"
    generic_eval_9files=$(find . -type f -name "*.php" -exec grep -lP "\<\?php\s\\\$[a-zA-Z0-9]+\=\'[a-zA-Z0-9]+\([a-zA-Z0-9$_]+\\\'[a-zA-Z0-9$_]+\'\;if\(isset\(\\\$\{(\\\$[a-zA-Z0-9]+\[[0-9]+\]\.){6}\\\$[a-zA-Z0-9]+\[[0-9]+\]\}" {} \;)
    printf "%s\n" "$generic_eval_9files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_uploader_72 {
    # Finds Malware.Expert.Generic.Uploader.4 infections
    echo "generic_uploader_72"
    generic_uploader_72files=$(find . -type f -exec grep -lP "echo\s\'JSSPWNED\!\<br\/\>\<form\saction\=" {} \;)
    printf "%s\n" "$generic_uploader_72files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_mailer_19 {
    # Finds Malware.Expert.Generic.Mailer.19 infections
    echo "generic_mailer_19"
    generic_mailer_19files=$(find . -type f -exec grep -lP 'loader\.php\?email\=\$login\&\.rand\=13InboxLight\.aspx\?n\=1774256418\&fid\=4\#n\=1252899642\&fid\=1\&fav\=1\"\)\;' {} \;)
    printf "%s\n" "$generic_mailer_19files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_preg_replace_post_11 {
    # Finds Malware.Expert.Generic.Preg.Replace.Post.11 infections
    echo "preg_replace_post_11"
    generic_preg_replace_post11files=$(find . -type f -exec grep -lP "\<\?php\sif\s\(\!isset\(\\\$\_REQUEST\[\'e[0-9][0-9]e\'\]\)\)\sheader\(" {} \;)
    printf "%s\n" "$generic_preg_replace_post11files" >> $workingdirectory/arquivos-infectados.log
    cd /tmp
    generic_preg_replace_post11Bfiles=$(find . -type f -exec grep -lP "\<\?php\sif\s\(\!isset\(\\\$\_REQUEST\[\'e[0-9][0-9]e\'\]\)\)\sheader\(" {} \;)
    printf "%s\n" "$generic_preg_replace_post11Bfiles" >> $workingdirectory/arquivos-infectados.log
    cd $workingdirectory
}

function general_remove_malware_expert_generic_malware_86 {
    # Finds Malware.Expert.Generic.Malware.86 infections
    echo "generic_malware_86"
    generic_malware_86files=$(find . -type f -name "*.php" -exec grep -lP "\{(\\\$[a-zA-Z]+.){2,}\.\\\$[a-zA-Z0-9]+\}\;if\(isset\(\\\$[\/*a-zA-Z0-9]+\[\'[a-zA-Z]+\'\]\)\)\{\\\$[a-zA-Z0-9]+\=[\/*\\\$\@!=a-zA-Z0-9]+\[\'[a-zA-Z0-9]+\'\]\." {} \;)
    printf "%s\n" "$generic_malware_86files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_malware_159 {
    # Finds Malware.Expert.Generic.Malware.159 infections
    echo "generic_malware_159"
    generic_malware_159files=$(find . -type f -exec grep -lP "\<\?php\sif\(\!class\_exists\(\'Ratel\'\)\)\{if\(function\_exists\(\'is\_user\_logged\_in\'\)\)\{if\(is\_user\_logged\_in\(\)\)\{return\sfalse\;\}\}if\(\@preg\_match" {} \;)
    printf "%s\n" "$generic_malware_159files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_win_trojan_hide_2 {
    echo "win_trojan_hide_2"
    win_trojan_hide_2files=$(find . -type f -exec grep -lP '\<\?php\secho\s\"RKntC\-InJ\"\s\.\s\"eCt\.\"\.\"TeSt\"\;\?\>' {} \;)
    printf "%s\n" "$win_trojan_hide_2files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_malware_7 {
    # Finds Malware.Expert.Generic.Malware.7 infections
    echo "generic_malware_7"
    generic_malware_7files=$(find . -type f -name "*.php" -exec grep -lP "(\\\$[a-zA-Z0-9]+\[\'[a-zA-Z0-9]+\'\]\[[0-9]+\]\.){10}" {} \;)
    printf "%s\n" "$generic_malware_7files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_cookie_7 {
    # Finds Malware.Expert.Generic.Cookie.7 infections
    echo "generic_cookie_7"
    generic_cookie_7files=$(find . -type f -name "*.php" -exec grep -lP "\<\?php\sif\(isset\(\\\$\_COOKIE\[\"[a-zA-Z]+\"\]\)\)\{\\\$\_COOKIE\[\"[a-zA-Z]+\"\]\(\\\$\_COOKIE\[\"[a-zA-Z]+\"\]\)\;exit\;\}" {} \;)
    printf "%s\n" "$generic_cookie_7files" >> $workingdirectory/arquivos-infectados.log
}

function general_remove_malware_expert_generic_eval_base64_decode_0 {
    # Finds Malware.Expert.Generic.Eval.Base64.Decode.0 infections
    echo "generic_eval_base64_decode_0"
    generic_eval_base64_decode_0files=$(find . -type f -name "haccess.php" -exec grep -lP '\<\?php\seval\(base64\_decode\(\"[a-zA-Z0-9+]+\"\)\)\;\s\?\>' {} \;)
    printf "%s\n" "$generic_eval_base64_decode_0files" >> $workingdirectory/arquivos-infectados.log
}

############################### Create Restore Point ########################################
#  Cria um backup dos arquivos, pastas e banco de dados para restaurar em caso de problemas.#
#############################################################################################
function create_backup {
    echo "Will be added in next release!"
  # Função chegando na próxima atualização!
}

##################### Restaurar backup do ponto de restauração ###############################
#  Cria um backup dos arquivos, pastas e banco de dados para restaurar em caso de problemas.#
#############################################################################################
function restore_backup {
    echo "Will be added in next release!"
  # Função chegando na próxima atualização!
}

################################ Substituição do Core ##################################
#     Substitui os arquivos principais do WordPress por novas versões da mesma versão. #
########################################################################################
function sweep_wp_core {
    # Limpe a tela primeiro
    clear
    # Aviso na tela
    echo "Verificando versão do WordPress $version. Substituindo arquivos."
    echo "Por favor, espere..."
    # Mova para a pasta temporária e verifique se a versão atual está presente em /tmp, caso contrário, baixe o arquivo zip da versão
    cd /tmp
        if [ ! -f wordpress-"$version".zip ]; then
            wget -q https://wordpress.org/wordpress-"$version".zip
        else
            rm -rf wordpress-"$version".zip
            wget -q https://wordpress.org/wordpress-"$version".zip
        fi
    # Extrair arquivo zip
    unzip -q wordpress-"$version".zip
    # Remover arquivo zip
    rm -rf wordpress-"$version".zip
    # Vá para o WordPress instalado e remova arquivos e pastas (exceto wp-config.php)
    cd "$workingdirectory"
    rm -rf {wp-admin,wp-includes}
    rm -rf {wp-activate.php,wp-blog-header.php,wp-comments-post.php,wp-config-sample.php,wp-cron.php,wp-links-opml.php,wp-load.php,wp-login.php,wp-mail.php,wp-signup.php,wp-trackback.php,xmlrpc.php}
    # Vá para a versão baixada e copie os arquivos e pastas (exceto wp-config.php) para o diretório de trabalho
    cd /tmp/wordpress/
    cp -r {wp-admin,wp-includes} "$workingdirectory"/
    cp {index.php,wp-activate.php,wp-blog-header.php,wp-comments-post.php,wp-cron.php,wp-links-opml.php,wp-load.php,wp-login.php,wp-mail.php,wp-settings.php,wp-signup.php,wp-trackback.php,xmlrpc.php} "$workingdirectory"/
    # Remova a pasta WordPress descompactada depois de copiar os arquivos
    cd "$workingdirectory"
    rm -rf /tmp/wordpress/
    # Adicionar versão substituída ao arquivo de log scan-wordpane
    echo "######### WordPress Core #########" >> $workingdirectory/scan-wordpane-$datetime.log
    echo "" >> $workingdirectory/scan-wordpane-$datetime.log
    echo "Substituído a versão $version do WordPress por novos arquivos do repositório WordPress.org." >> $workingdirectory/scan-wordpane-$datetime.log
    echo "" >> $workingdirectory/scan-wordpane-$datetime.log
    # Limpe a tela e volte ao menu
    gotomenu
}

################################ Substituição de plugins ################################
#     Substitui os arquivos de plug-in do WordPress por novas versões da mesma versão.  #
#########################################################################################
function plugin_start_logentry {
    echo "Substituindo plugins gratuitos por uma nova versão do repositório WordPress.org."
    echo "######### WordPress Plugins #########" >> $workingdirectory/scan-wordpane-$datetime.log
    echo "" >> $workingdirectory/scan-wordpane-$datetime.log
    echo "Abaixo você encontrará os plugins que foram substituídos com sucesso por uma nova versão, baixados do repositório WordPress.org." >> $workingdirectory/scan-wordpane-$datetime.log
    echo "Se uma substituição estiver listada como FALHOU, isso é causado por um destes motivos:" >> $workingdirectory/scan-wordpane-$datetime.log
    echo "- O plugin é um plugin premium (que não podemos substituir automaticamente para você)." >> $workingdirectory/scan-wordpane-$datetime.log
    echo "- O plugin foi removido do repositório WordPress.org." >> $workingdirectory/scan-wordpane-$datetime.log
    echo "- O plugin é um código desenvolvido personalizado que não é publicado no repositório de plug-ins do WordPress.org." >> $workingdirectory/scan-wordpane-$datetime.log
    echo "" >> $workingdirectory/scan-wordpane-$datetime.log
    echo ""
    echo "Procedimento em execução:"
    echo ""
}

function get_plugin_version {
    # Obtenha a versão do plugin e coloque-a na variável $pluginversion
    if [ -f "$plugin/$plugin.php" ]; then
        pluginversion=$(grep Version $plugin/$plugin.php | egrep -o "([0-9]{1,}\.)+[0-9]{1,}"| head -1)
    else
        pluginversion=$(echo '')
    fi
}

function sweep_plugin_noversion {
    # A variável está vazia, versão não definida
    cd /tmp
    wget -q https://downloads.wordpress.org/plugin/$plugin.zip
    # Verifique se está presente e implante  
    if test -f "/tmp/$plugin.zip"; then
        mv $plugin.zip $workingdirectory/wp-content/plugins/
        cd $workingdirectory/wp-content/plugins
        rm -rf $workingdirectory/wp-content/plugins/$plugin
        unzip -q $workingdirectory/wp-content/plugins/$plugin.zip
        rm -rf $plugin.zip
        echo "SUCESSO: $plugin" >> $workingdirectory/scan-wordpane-$datetime.log;
    else
        # Plugin não encontrado - relatórios
        echo "FALHOU: $plugin não foi substituído. Não disponível para download no repositório de plugins wordpress.org." >> $workingdirectory/scan-wordpane-$datetime.log;
    fi
}

function sweep_plugin_withversion {
    # A variável contém o valor, a versão está definida
    cd /tmp
    wget -q https://downloads.wordpress.org/plugin/$plugin.$pluginversion.zip
    # Verifique se está presente e implante 
    if test -f "/tmp/$plugin.$pluginversion.zip"; then
        mv $plugin.$pluginversion.zip $workingdirectory/wp-content/plugins/
        cd $workingdirectory/wp-content/plugins
        rm -rf $workingdirectory/wp-content/plugins/$plugin
        unzip -q $workingdirectory/wp-content/plugins/$plugin.$pluginversion.zip
        rm -rf $plugin.$pluginversion.zip
        echo "SUCESSO: $plugin $pluginversion" >> $workingdirectory/scan-wordpane-$datetime.log;
    else
        # Plugin não encontrado - relatórios
        echo "FALHOU: $plugin $pluginversion não foi substituído. Não disponível para download no repositório de plugins wordpress.org." >> $workingdirectory/scan-wordpane-$datetime.log;
    fi
}

function sweep_wp_plugins {
    # Função Runner para a lógica de substituição do plugin.
    clear
    plugin_start_logentry
    # Verifique se wp-content/plugins está acessível e, em seguida, faça o cd nele.
    if [[ -d wp-content/plugins ]]
        then 
        cd wp-content/plugins/
        # Execute um loop indexando todos os plugins.
        for plugin in $(ls -d */ | cut -f1 -d'/'); do
            get_plugin_version
            if [ "$plugin" == "index.php" ]; then 
                continue
            elif [ -z "$pluginversion" ]; then
                echo $plugin
                sweep_plugin_noversion
            else
                echo $plugin
                sweep_plugin_withversion
            fi
        done
        cd $workingdirectory
    else
        echo "FALHOU: diretório "wp-content/plugins" não estava acessível/presente." >> $workingdirectory/scan-wordpane-$datetime.log;
    fi
    echo "" >> $workingdirectory/scan-wordpane-$datetime.log;
    # Limpe a tela e volte ao menu
    gotomenu
}

################################ Substituição de tema ######################################
#     Substitui os arquivos de tema do WordPress por novas versões do mesmo lançamento.    #
###########################################################################################
function sweep_wp_themes {
    clear
    echo "Substituindo temas gratuitos por uma nova versão do repositório WordPress.org..."
    echo ""
    echo "######### WordPress Temas #########" >> $workingdirectory/scan-wordpane-$datetime.log
    echo "" >> $workingdirectory/scan-wordpane-$datetime.log
    echo "Abaixo você encontrará os temas que foram substituídos com sucesso por uma nova versão, baixados do repositório de temas do WordPress.org." >> $workingdirectory/scan-wordpane-$datetime.log
    echo "Se uma substituição estiver listada como FALHOU, isso é causado por um destes motivos:" >> $workingdirectory/scan-wordpane-$datetime.log
    echo "- O tema é um tema premium (que não podemos substituir automaticamente para você)." >> $workingdirectory/scan-wordpane-$datetime.log
    echo "- O tema foi removido do repositório WordPress.org." >> $workingdirectory/scan-wordpane-$datetime.log
    echo "- O tema é um tema desenvolvido sob medida que não é publicado no repositório de temas do WordPress.org." >> $workingdirectory/scan-wordpane-$datetime.log
    echo "" >> $workingdirectory/scan-wordpane-$datetime.log
        if [[ -d wp-content/themes ]]
        then 
            cd wp-content/themes/
                for theme in $(ls -d */ | cut -f1 -d'/'); do
                    cd /tmp
                    wget -q https://downloads.wordpress.org/theme/$theme.zip
                    # Verifique se está presente e implante
                    if test -f "/tmp/$theme.zip"; then 
                        cp $theme.zip $workingdirectory/wp-content/themes/
                        cd $workingdirectory/wp-content/themes
                        rm -rf $workingdirectory/wp-content/themes/$theme
                        unzip -q $workingdirectory/wp-content/themes/$theme.zip
                        rm -rf $theme.zip
                        echo "SUCESSO: $theme" >> $workingdirectory/scan-wordpane-$datetime.log;
                    else
                        # Tema não encontrado - relatórios
                        echo "FALHOU: $theme não foi substituído. Não disponível no repositório de temas wordpress.org." >> $workingdirectory/scan-wordpane-$datetime.log;
                    fi
                done
            cd $workingdirectory
        else
            echo "FALHOU: diretório "wp-content/themes" não estava acessível/presente." >> $workingdirectory/scan-wordpane-$datetime.log;
        fi
    echo "" >> $workingdirectory/scan-wordpane-$datetime.log;
    # Limpe a tela e volte ao menu
    gotomenu
}

################################## Malware Scan #############################################
#        Verifica todo o diretório de trabalho em busca de arquivos maliciosos ou suspeitos.#
#############################################################################################
function sweep_malware_scan {
    clear
    echo "Executando uma verificação de malware em seu site."
    echo "Aguarde... Isso pode demorar um pouco."
    echo ""
    echo "######### Malware Scan #########" >> $workingdirectory/scan-wordpane-$datetime.log
    echo "" >> $workingdirectory/scan-wordpane-$datetime.log
    echo "Os arquivos maliciosos ou suspeitos foram encontrados:" >> $workingdirectory/scan-wordpane-$datetime.log
    echo "" >> $workingdirectory/scan-wordpane-$datetime.log
    # Funções para executar as varreduras de assinatura individuais:
    general_remove_inputfiles
    general_remove_ico
    general_remove_suspected
    # Assinaturas do tipo de infecção Maldet abaixo
    general_remove_cmb_base64decode_hex
    general_remove_dropsforums_ru_bruteforce_1
    general_remove_malware_expert_b374k_shell_3
    general_remove_malware_expert_filebox_1
    general_remove_malware_expert_generic_cookie_7
    general_remove_malware_expert_generic_create_function_10
    general_remove_malware_expert_generic_encoded_zip_file_0
    general_remove_malware_expert_generic_eval_27
    general_remove_malware_expert_generic_eval_79
    general_remove_malware_expert_generic_eval_82
    general_remove_malware_expert_generic_eval_base64_decode_0
    general_remove_malware_expert_generic_eval_base64_decode_14
    general_remove_malware_expert_generic_eval_base64_decode_24
    general_remove_malware_expert_generic_eval_base64_post_3
    general_remove_malware_expert_generic_eval_gzinflate_base64_15
    general_remove_malware_expert_generic_eval_post_0
    general_remove_malware_expert_generic_eval_post_8
    general_remove_malware_expert_generic_fwrite_htaccess_4
    general_remove_malware_expert_generic_mailer_19
    general_remove_malware_expert_generic_malware_7
    general_remove_malware_expert_generic_malware_41
    general_remove_malware_expert_generic_malware_86
    general_remove_malware_expert_generic_malware_98
    general_remove_malware_expert_generic_malware_124
    general_remove_malware_expert_generic_malware_135
    general_remove_malware_expert_generic_malware_136
    general_remove_malware_expert_generic_malware_155
    general_remove_malware_expert_generic_malware_158
    general_remove_malware_expert_generic_malware_165
    general_remove_malware_expert_generic_malware_172
    general_remove_malware_expert_generic_malware_178
    general_remove_malware_expert_generic_malware_189
    general_remove_malware_expert_generic_malware_444
    general_remove_malware_expert_generic_preg_replace_post_11
    general_remove_malware_expert_generic_uploader_4
    general_remove_malware_expert_generic_uploader_6
    general_remove_malware_expert_leaf_mailer_0
    general_remove_malware_expert_php_print_md5_0
    general_remove_malware_expert_steal_user_pass_2
    general_remove_malware_expert_webShellOrb_web_shell_0
    general_remove_malware_expert_wordpress_file_put_contents_1
    general_remove_php_base64_v23au_187
    general_remove_php_cmdshell_cih_233
    general_remove_php_cmdshell_egyspider_240
    general_remove_php_cmdshell_generic_276
    general_remove_php_malware_magento_594
    general_remove_php_nested_base64_641
    general_remove_php_shell_black_id_700
    general_remove_php_uploader_max_706
    general_remove_win_trojan_hide_2
    # Coloque o conteúdo da lista de infecção na variável
    infections=$(cat $workingdirectory/arquivos-infectados.log)
    # Verifique se o log da lista de infecções está vazio ou não.
    if [ -z $workingdirectory/arquivos-infectados.log ]; then
        echo "Nenhuma infecção conhecida ou arquivo suspeito detectado. Tudo em pleno funcionamento!" >> $workingdirectory/scan-wordpane-$datetime.log
    else 
        cat $workingdirectory/arquivos-infectados.log >> $workingdirectory/scan-wordpane-$datetime.log
    fi
    # Remover arquivos-infectados.log
    rm -rf arquivos-infectados.log
    # Limpe a tela e volte ao menu
    gotomenu
}

####################################### Exit ############################################
#                       Limpeza antes da execução do comando de saída.                  #
#########################################################################################
function prepare_to_exit {
    # Limpe a pasta tmp
    # Limpe os arquivos-infectados.log
    # Termine limpando a tela
    clear
}

####################################### Menu ############################################
#         Desenha o menu na tela. É acionado pela função do corredor abaixo.            #
#########################################################################################
function wpsweeper_menu {
    clear
    display_logo
    echo "Selecione digitando o número correspondente.   "
    echo "                                                      "

select choice in \
    "Limpeza dos arquivos do Core WordPress" \
    "Limpeza dos arquivos dos plugins" \
    "Limpeza dos arquivos do tema" \
    "Scan WordPane" \
    "Sair"
do
    case $choice in
        "Limpeza dos arquivos do Core WordPress")
            sweep_wp_core;
            ;;
        "Limpeza dos arquivos dos plugins")
            sweep_wp_plugins;
            ;;
        "Limpeza dos arquivos do tema")
            sweep_wp_themes;
            ;;
        "Scan WordPane")
            sweep_malware_scan;
            ;;
        "Sair")
            prepare_to_exit;
            exit;
            ;;
        *)
            echo "Selecione digitando o número correspondente.";
            ;;
    esac
done

clear
}

# Limpe a tela e volte ao menu
function gotomenu {
    clear
    display_logo
    wpsweeper_menu
}

###################################### Runner ###########################################
#     Inicia o script. Acionará a função de menu acima na inicialização.                #
#########################################################################################
initialize_logfile
wpsweeper_menu
