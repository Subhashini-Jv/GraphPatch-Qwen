package demo;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/** Deliberately vulnerable demo (zip slip, CWE-22) so the GitHub Action has something to report. */
public class Unzip {
    public static void extract(ZipFile zip, File targetDir) throws IOException {
        Enumeration<? extends ZipEntry> entries = zip.entries();
        while (entries.hasMoreElements()) {
            ZipEntry entry = entries.nextElement();
            File out = new File(targetDir, entry.getName());
            try (InputStream in = zip.getInputStream(entry); FileOutputStream fos = new FileOutputStream(out)) {
                in.transferTo(fos);
            }
        }
    }
}
