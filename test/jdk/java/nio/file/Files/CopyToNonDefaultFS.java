/*
 * Copyright (c) 2022, 2024, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

/**
 * @test
 * @bug 8245194
 * @run main/othervm CopyToNonDefaultFS
 * @summary Test for exception copying from default to non-default file system
 */

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.*;
import java.nio.file.*;
import java.util.*;

import static java.nio.file.StandardOpenOption.*;

public class CopyToNonDefaultFS {
    public static void main(String... args) throws IOException {
        Path source = Files.createTempFile(Path.of("."), "tmp", ".dat");
        try (FileChannel fc = FileChannel.open(source, CREATE, WRITE)) {
            fc.position(8191);
            fc.write(ByteBuffer.wrap(new byte[] {27}));
        }

        Path zip = Path.of("out.zip");
        zip.toFile().deleteOnExit();
        Map<String,String> env =
            Map.of("create", String.valueOf(Files.notExists(zip)));

        ClassLoader cl = CopyToNonDefaultFS.class.getClassLoader();
        try (FileSystem fileSystem = FileSystems.newFileSystem(zip, env, cl)) {
            Path p = fileSystem.getPath(source.getFileName().toString());
            Files.copy(source, p);
        }
    }
}
