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
    'zh_CN' => 'Chinese (Simplified)',
    'ar'    => 'Arabic',
    'hi_IN' => 'Hindi',
    'ko_KR' => 'Korean',
    'tr_TR' => 'Turkish',
    'pl_PL' => 'Polish',
    'id_ID' => 'Indonesian',
    'uk'    => 'Ukrainian',
    'vi'    => 'Vietnamese',
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
        'es_ES' => 'Configuración General', 'fr_FR' => 'Réglages Généraux', 'de_DE' => 'Allgemeine Einstellungen', 'it_IT' => 'Impostazioni Generali', 'pt_BR' => 'Configurações Gerais',
        'nl_NL' => 'Algemene Instellingen', 'ru_RU' => 'Общие Настройки', 'ja' => '一般設定', 'zh_CN' => '常规设置', 'ar' => 'الإعدادات العامة',
        'hi_IN' => 'सामान्य सेटिंग्स', 'ko_KR' => '일반 설정', 'tr_TR' => 'Genel Ayarlar', 'pl_PL' => 'Ustawienia Ogólne', 'id_ID' => 'Pengaturan Umum',
        'uk' => 'Загальні налаштування', 'vi' => 'Cài đặt chung', 'th' => 'การตั้งค่าทั่วไป', 'sv_SE' => 'Allmänna Inställningar', 'da_DK' => 'Generelle Indstillinger',
    ),
    'Save Settings' => array(
        'es_ES' => 'Guardar Configuración', 'fr_FR' => 'Enregistrer', 'de_DE' => 'Einstellungen Speichern', 'it_IT' => 'Salva Impostazioni', 'pt_BR' => 'Salvar Configurações',
        'nl_NL' => 'Instellingen Opslaan', 'ru_RU' => 'Сохранить Настройки', 'ja' => '設定を保存', 'zh_CN' => '保存设置', 'ar' => 'حفظ الإعدادات',
        'hi_IN' => 'सेटिंग्स सहेजें', 'ko_KR' => '설정 저장', 'tr_TR' => 'Ayarları Kaydet', 'pl_PL' => 'Zapisz Ustawienia', 'id_ID' => 'Simpan Pengaturan',
        'uk' => 'Зберегти налаштування', 'vi' => 'Lưu cài đặt', 'th' => 'บันทึกการตั้งค่า', 'sv_SE' => 'Spara Inställningar', 'da_DK' => 'Gem Indstillinger',
    ),
    'Plugin Language' => array(
        'es_ES' => 'Idioma del Plugin', 'fr_FR' => 'Langue du Plugin', 'de_DE' => 'Plugin-Sprache', 'it_IT' => 'Lingua del Plugin', 'pt_BR' => 'Idioma do Plugin',
        'nl_NL' => 'Plugin Taal', 'ru_RU' => 'Язык Плагина', 'ja' => 'プラグイン言語', 'zh_CN' => '插件语言', 'ar' => 'لغة الإضافة',
        'hi_IN' => 'प्लगइन भाषा', 'ko_KR' => '플러그인 언어', 'tr_TR' => 'Eklenti Dili', 'pl_PL' => 'Język Wtyczki', 'id_ID' => 'Bahasa Plugin',
        'uk' => 'Мова плагіна', 'vi' => 'Ngôn ngữ Plugin', 'th' => 'ภาษาปลั๊กอิน', 'sv_SE' => 'Dinsticksprogram Språk', 'da_DK' => 'Plugin Sprog',
    ),
    'Email Notifications' => array(
        'es_ES' => 'Notificaciones por Email', 'fr_FR' => 'Notifications par Email', 'de_DE' => 'E-Mail-Benachrichtigungen', 'it_IT' => 'Notifiche Email', 'pt_BR' => 'Notificações por E-mail',
        'nl_NL' => 'E-mail Meldingen', 'ru_RU' => 'Email Уведомления', 'ja' => 'メール通知', 'zh_CN' => '邮件通知', 'ar' => 'إشعارات البريد الإلكتروني',
        'hi_IN' => 'ईमेल सूचनाएं', 'ko_KR' => '이메일 알림', 'tr_TR' => 'E-posta Bildirimleri', 'pl_PL' => 'Powiadomienia Email', 'id_ID' => 'Notifikasi Email',
        'uk' => 'Email сповіщення', 'vi' => 'Thông báo qua Email', 'th' => 'การแจ้งเตือนอีเมล', 'sv_SE' => 'E-postaviseringar', 'da_DK' => 'E-mail Notifikationer',
    ),
    'Auto-Updates' => array(
        'es_ES' => 'Actualizaciones Automáticas', 'fr_FR' => 'Mises à jour auto', 'de_DE' => 'Automatische Updates', 'it_IT' => 'Aggiornamenti Auto', 'pt_BR' => 'Atualizações Automáticas',
        'nl_NL' => 'Automatische Updates', 'ru_RU' => 'Автообновления', 'ja' => '自動更新', 'zh_CN' => '自动更新', 'ar' => 'التحديثات التلقائية',
        'hi_IN' => 'स्वचालित अपडेट', 'ko_KR' => '자동 업데이트', 'tr_TR' => 'Otomatik Güncellemeler', 'pl_PL' => 'Automatyczne Aktualizacje', 'id_ID' => 'Pembaruan Otomatis',
        'uk' => 'Автооновлення', 'vi' => 'Cập nhật tự động', 'th' => 'อัปเดตอัตโนมัติ', 'sv_SE' => 'Automatiska Uppdateringar', 'da_DK' => 'Automatiske Opdateringer',
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
