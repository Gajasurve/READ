rule url {
    meta:
        author = "Bhosidika"
    strings:
        $url_regex = /https?:\/\/([\w\.-]+)([\/\w \.-]*)/ wide ascii
    condition:
        $url_regex
}
