package com.ft.web.rest.app;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import net.glxn.qrgen.javase.QRCode;

/**
 * REST controller for populate data into Dashboard portal
 */
@Controller
@RequestMapping("/api/web-service")
public class QrCodeResource {

    private final Logger log = LoggerFactory.getLogger(QrCodeResource.class);

    @GetMapping(value = "/qr-code", produces = MediaType.IMAGE_PNG_VALUE)
    public @ResponseBody byte[] getImage(
    		@RequestParam("text") String text,
    		@RequestParam(value="size", required=false, defaultValue="200") Integer size
    ) throws IOException {
    	log.debug("Generate QR Image of type PNG for text [" + text + "] size " + size);
        return QRCode.from(text)
        		.withSize(size, size)
        		.stream()
        		.toByteArray();
    }
}
