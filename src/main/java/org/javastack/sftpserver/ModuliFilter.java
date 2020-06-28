package org.javastack.sftpserver;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * @see org.apache.sshd.server.kex.Moduli
 */
public class ModuliFilter {
	public static final int MODULI_TYPE_SAFE = 2;
	public static final int MODULI_TESTS_COMPOSITE = 0x01;

	public static ArrayList<String> filterModuli(final URL url, final int minSize, final int maxSize)
			throws IOException {
		final ArrayList<String> parsed = new ArrayList<>();
		try (BufferedReader r = new BufferedReader(new InputStreamReader(url.openStream(), StandardCharsets.UTF_8))) {
			for (String line = r.readLine(); line != null; line = r.readLine()) {
				line = line.trim();
				if (line.isEmpty()) {
					continue;
				}

				if (line.startsWith("#")) {
					continue;
				}

				String[] parts = line.split("\\s+");
				// Ensure valid line
				if (parts.length != 7) {
					continue;
				}

				// Discard moduli types which are not safe
				int type = Integer.parseInt(parts[1]);
				if (type != MODULI_TYPE_SAFE) {
					continue;
				}

				// Discard untested moduli
				int tests = Integer.parseInt(parts[2]);
				if (((tests & MODULI_TESTS_COMPOSITE) != 0) || ((tests & ~MODULI_TESTS_COMPOSITE) == 0)) {
					continue;
				}

				// Discard untried
				int tries = Integer.parseInt(parts[3]);
				if (tries == 0) {
					continue;
				}

				// Discard unwanted sizes
				int size = Integer.parseInt(parts[4]);
				if ((size < minSize) || (size > maxSize)) {
					continue;
				}

				parsed.add(line);
			}

			return parsed;
		}
	}

	public static void writeModuli(final File file, final List<String> lines) throws IOException {
		try (BufferedWriter r = new BufferedWriter(
				new OutputStreamWriter(new FileOutputStream(file), StandardCharsets.UTF_8))) {
			for (final String str : lines) {
				r.write(str);
				r.newLine();
			}
		}
	}
}
