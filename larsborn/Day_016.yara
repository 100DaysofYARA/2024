rule EmailWithZipAttachment {
    meta:
        description = "Some common email headers together with base64 encoded start of a ZIP file"
        author = "@larsborn"
        date = "2024-02-06"
        reference = "https://en.wikipedia.org/wiki/Base64"
        example_hash = "941e4a04ea1ffca986f3ae78f7d0a9bc5483464a679e6ea49a5f4ab8e7e92c03"

        DaysofYARA = "16/100"
    strings:
        $email_headers_01 = "Received: "
        $email_headers_02 = "From: "
        $email_headers_03 = "Date: "
        $email_headers_04 = "Subject: "
        $email_headers_05 = "To: "
        $attachment_headers_01 = "Content-Type: text/html; "
        $attachment_headers_02 = "Content-Type: application/octet-stream; name="
        $attachment_headers_03 = "Content-Disposition: attachment; filename="
        $attachment_headers_04 = "Content-Transfer-Encoding: base64"
        $base64_zip_attachment = { 0d 0a 0d 0a 55 45 73 44 42 }
    condition:
        all of them
}
