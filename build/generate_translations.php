<?php
/**
 * Batch Translation Generator
 * Generates PO files for all supported languages and compiles them to MO.
 * Note: Uses placeholder translations (English source) to create valid files.
 */

$languages = array(
    'es_ES' => 'Spanish',
    'fr_FR' => 'French',
    'de_DE' => 'German',
    'it_IT' => 'Italian',
    'pt_BR' => 'Portuguese (Brazil)',
    'nl_NL' => 'Dutch',
    'ru_RU' => 'Russian',
    'ja'    => 'Japanese',
    'zh_Hans' => 'Chinese (Simplified)',
    'ar'    => 'Arabic',
    'hi_IN' => 'Hindi',
    'ko_KR' => 'Korean',
    'tr'    => 'Turkish',
    'pl_PL' => 'Polish',
    'id_ID' => 'Indonesian',
    'uk_UA' => 'Ukrainian',
    'vi_VN' => 'Vietnamese',
    'th'    => 'Thai',
    'sv_SE' => 'Swedish',
    'da_DK' => 'Danish',
    'fi'    => 'Finnish',
    'no'    => 'Norwegian',
    'cs_CZ' => 'Czech',
    'el'    => 'Greek',
    'hu_HU' => 'Hungarian',
    'ro_RO' => 'Romanian',
    'sk_SK' => 'Slovak',
    'bg_BG' => 'Bulgarian',
    'hr'    => 'Croatian',
    'sr_RS' => 'Serbian',
    'he_IL' => 'Hebrew',
    'fa_IR' => 'Persian',
);

// Dictionary of key UI terms
$dictionary = array(
    'General Settings' => array(
        'es_ES' => 'ConfiguraciÃ³n General', 'fr_FR' => 'RÃ©glages GÃ©nÃ©raux', 'de_DE' => 'Allgemeine Einstellungen', 'it_IT' => 'Impostazioni Generali', 'pt_BR' => 'ConfiguraÃ§Ãµes Gerais',
        'nl_NL' => 'Algemene Instellingen', 'ru_RU' => 'ÐžÐ±Ñ‰Ð¸Ðµ ÐÐ°ÑÑ‚Ñ€Ð¾Ð¹ÐºÐ¸', 'ja' => 'ä¸€èˆ¬è¨­å®š', 'zh_Hans' => 'å¸¸è§„è®¾ç½®', 'ar' => 'Ø§Ù„Ø¥Ø¹Ø¯Ø§Ø¯Ø§Øª Ø§Ù„Ø¹Ø§Ù…Ø©',
        'hi_IN' => 'à¤¸à¤¾à¤®à¤¾à¤¨à¥à¤¯ à¤¸à¥‡à¤Ÿà¤¿à¤‚à¤—à¥à¤¸', 'ko_KR' => 'ì¼ë°˜ ì„¤ì •', 'tr' => 'Genel Ayarlar', 'pl_PL' => 'Ustawienia OgÃ³lne', 'id_ID' => 'Pengaturan Umum',
        'uk_UA' => 'Ð—Ð°Ð³Ð°Ð»ÑŒÐ½Ñ– Ð½Ð°Ð»Ð°ÑˆÑ‚ÑƒÐ²Ð°Ð½Ð½Ñ', 'vi_VN' => 'CÃ i Ä‘áº·t chung', 'th' => 'à¸à¸²à¸£à¸•à¸±à¹‰à¸‡à¸„à¹ˆà¸²à¸—à¸±à¹ˆà¸§à¹„à¸›', 'sv_SE' => 'AllmÃ¤nna InstÃ¤llningar', 'da_DK' => 'Generelle Indstillinger',
    ),
    'Save Settings' => array(
        'es_ES' => 'Guardar ConfiguraciÃ³n', 'fr_FR' => 'Enregistrer', 'de_DE' => 'Einstellungen Speichern', 'it_IT' => 'Salva Impostazioni', 'pt_BR' => 'Salvar ConfiguraÃ§Ãµes',
        'nl_NL' => 'Instellingen Opslaan', 'ru_RU' => 'Ð¡Ð¾Ñ…Ñ€Ð°Ð½Ð¸Ñ‚ÑŒ ÐÐ°ÑÑ‚Ñ€Ð¾Ð¹ÐºÐ¸', 'ja' => 'è¨­å®šã‚’ä¿å­˜', 'zh_Hans' => 'ä¿å­˜è®¾ç½®', 'ar' => 'Ø­ÙØ¸ Ø§Ù„Ø¥Ø¹Ø¯Ø§Ø¯Ø§Øª',
        'hi_IN' => 'à¤¸à¥‡à¤Ÿà¤¿à¤‚à¤—à¥à¤¸ à¤¸à¤¹à¥‡à¤œà¥‡à¤‚', 'ko_KR' => 'ì„¤ì • ì €ìž¥', 'tr' => 'AyarlarÄ± Kaydet', 'pl_PL' => 'Zapisz Ustawienia', 'id_ID' => 'Simpan Pengaturan',
        'uk_UA' => 'Ð—Ð±ÐµÑ€ÐµÐ³Ñ‚Ð¸ Ð½Ð°Ð»Ð°ÑˆÑ‚ÑƒÐ²Ð°Ð½Ð½Ñ', 'vi_VN' => 'LÆ°u cÃ i Ä‘áº·t', 'th' => 'à¸šà¸±à¸™à¸—à¸¶à¸à¸à¸²à¸£à¸•à¸±à¹‰à¸‡à¸„à¹ˆà¸²', 'sv_SE' => 'Spara InstÃ¤llningar', 'da_DK' => 'Gem Indstillinger',
    ),
    'Plugin Language' => array(
        'es_ES' => 'Idioma del Plugin', 'fr_FR' => 'Langue du Plugin', 'de_DE' => 'Plugin-Sprache', 'it_IT' => 'Lingua del Plugin', 'pt_BR' => 'Idioma do Plugin',
        'nl_NL' => 'Plugin Taal', 'ru_RU' => 'Ð¯Ð·Ñ‹Ðº ÐŸÐ»Ð°Ð³Ð¸Ð½Ð°', 'ja' => 'ãƒ—ãƒ©ã‚°ã‚¤ãƒ³è¨€èªž', 'zh_Hans' => 'æ’ä»¶è¯­è¨€', 'ar' => 'Ù„ØºØ© Ø§Ù„Ø¥Ø¶Ø§ÙØ©',
        'hi_IN' => 'à¤ªà¥à¤²à¤—à¤‡à¤¨ à¤­à¤¾à¤·à¤¾', 'ko_KR' => 'í”ŒëŸ¬ê·¸ì¸ ì–¸ì–´', 'tr' => 'Eklenti Dili', 'pl_PL' => 'JÄ™zyk Wtyczki', 'id_ID' => 'Bahasa Plugin',
        'uk_UA' => 'ÐœÐ¾Ð²Ð° Ð¿Ð»Ð°Ð³Ñ–Ð½Ð°', 'vi_VN' => 'NgÃ´n ngá»¯ Plugin', 'th' => 'à¸ à¸²à¸©à¸²à¸›à¸¥à¸±à¹Šà¸à¸­à¸´à¸™', 'sv_SE' => 'Dinsticksprogram SprÃ¥k', 'da_DK' => 'Plugin Sprog',
    ),
    'Email Notifications' => array(
        'es_ES' => 'Notificaciones por Email', 'fr_FR' => 'Notifications par Email', 'de_DE' => 'E-Mail-Benachrichtigungen', 'it_IT' => 'Notifiche Email', 'pt_BR' => 'NotificaÃ§Ãµes por E-mail',
        'nl_NL' => 'E-mail Meldingen', 'ru_RU' => 'Email Ð£Ð²ÐµÐ´Ð¾Ð¼Ð»ÐµÐ½Ð¸Ñ', 'ja' => 'ãƒ¡ãƒ¼ãƒ«é€šçŸ¥', 'zh_Hans' => 'é‚®ä»¶é€šçŸ¥', 'ar' => 'Ø¥Ø´Ø¹Ø§Ø±Ø§Øª Ø§Ù„Ø¨Ø±ÙŠØ¯ Ø§Ù„Ø¥Ù„ÙƒØªØ±ÙˆÙ†ÙŠ',
        'hi_IN' => 'à¤ˆà¤®à¥‡à¤² à¤¸à¥‚à¤šà¤¨à¤¾à¤à¤‚', 'ko_KR' => 'ì´ë©”ì¼ ì•Œë¦¼', 'tr' => 'E-posta Bildirimleri', 'pl_PL' => 'Powiadomienia Email', 'id_ID' => 'Notifikasi Email',
        'uk_UA' => 'Email ÑÐ¿Ð¾Ð²Ñ–Ñ‰ÐµÐ½Ð½Ñ', 'vi_VN' => 'ThÃ´ng bÃ¡o qua Email', 'th' => 'à¸à¸²à¸£à¹à¸ˆà¹‰à¸‡à¹€à¸•à¸·à¸­à¸™à¸­à¸µà¹€à¸¡à¸¥', 'sv_SE' => 'E-postaviseringar', 'da_DK' => 'E-mail Notifikationer',
    ),
    'Auto-Updates' => array(
        'es_ES' => 'Actualizaciones AutomÃ¡ticas', 'fr_FR' => 'Mises Ã  jour auto', 'de_DE' => 'Automatische Updates', 'it_IT' => 'Aggiornamenti Auto', 'pt_BR' => 'AtualizaÃ§Ãµes AutomÃ¡ticas',
        'nl_NL' => 'Automatische Updates', 'ru_RU' => 'ÐÐ²Ñ‚Ð¾Ð¾Ð±Ð½Ð¾Ð²Ð»ÐµÐ½Ð¸Ñ', 'ja' => 'è‡ªå‹•æ›´æ–°', 'zh_Hans' => 'è‡ªåŠ¨æ›´æ–°', 'ar' => 'Ø§Ù„ØªØ­Ø¯ÙŠØ«Ø§Øª Ø§Ù„ØªÙ„Ù‚Ø§Ø¦ÙŠØ©',
        'hi_IN' => 'à¤¸à¥à¤µà¤šà¤¾à¤²à¤¿à¤¤ à¤…à¤ªà¤¡à¥‡à¤Ÿ', 'ko_KR' => 'ìžë™ ì—…ë°ì´íŠ¸', 'tr' => 'Otomatik GÃ¼ncellemeler', 'pl_PL' => 'Automatyczne Aktualizacje', 'id_ID' => 'Pembaruan Otomatis',
        'uk_UA' => 'ÐÐ²Ñ‚Ð¾Ð¾Ð½Ð¾Ð²Ð»ÐµÐ½Ð½Ñ', 'vi_VN' => 'Cáº­p nháº­t tá»± Ä‘á»™ng', 'th' => 'à¸­à¸±à¸›à¹€à¸”à¸•à¸­à¸±à¸•à¹‚à¸™à¸¡à¸±à¸•à¸´', 'sv_SE' => 'Automatiska Uppdateringar', 'da_DK' => 'Automatiske Opdateringer',
    ),
);

$pot_file = dirname( __DIR__ ) . '/languages/nexifymy-security.pot';
$pot_content = file_get_contents( $pot_file );

foreach ( $languages as $code => $name ) {
    echo "Processing $name ($code)...\n";
    
    $po_file = dirname( __DIR__ ) . "/languages/nexifymy-security-$code.po";
    $mo_file = dirname( __DIR__ ) . "/languages/nexifymy-security-$code.mo";

    // Setup PO Header
    $po_content = preg_replace( '/Language-Team: LANGUAGE <LL@li.org>/', "Language-Team: $name <$code@nexifymy.com>", $pot_content );
    $po_content = preg_replace( '/Content-Type: text\/plain; charset=UTF-8/', 'Content-Type: text/plain; charset=UTF-8', $po_content );

    // Apply Dictionary Translations
    foreach ( $dictionary as $original => $translations ) {
        if ( isset( $translations[ $code ] ) ) {
            $trans = $translations[ $code ];
            // Precise replacement for msgid "Original" -> msgstr "Translated"
            // We use a regex specific to this entry to avoid replacing random text
            $po_content = preg_replace( 
                '/msgid "' . preg_quote( $original, '/' ) . '"\s*msgstr ""/', 
                'msgid "' . $original . '"' . "\n" . 'msgstr "' . $trans . '"', 
                $po_content 
            );
        }
    }

    file_put_contents( $po_file, $po_content );
    
    // Compile
    $cmd = "php " . __DIR__ . "/compile-mo.php \"$po_file\" \"$mo_file\"";
    passthru( $cmd );
    echo "\n";
}
echo "All languages processed.\n";

