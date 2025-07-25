/*
 * Copyright (c) 2020, 2025, Oracle and/or its affiliates. All rights reserved.
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

/*
 * @test
 * @key stress randomness
 * @bug 8252219 8256535 8317349 8319879 8335334 8325478
 * @requires vm.compiler2.enabled
 * @summary Tests that different combinations of stress options and
 *          -XX:StressSeed=N are accepted.
 * @run main/othervm -XX:+UnlockDiagnosticVMOptions -XX:+StressIGVN
 *      compiler.arguments.TestStressOptions
 * @run main/othervm -XX:+UnlockDiagnosticVMOptions -XX:+StressIGVN -XX:StressSeed=42
 *      compiler.arguments.TestStressOptions
 * @run main/othervm -XX:+UnlockDiagnosticVMOptions -XX:+StressCCP
 *      compiler.arguments.TestStressOptions
 * @run main/othervm -XX:+UnlockDiagnosticVMOptions -XX:+StressCCP -XX:StressSeed=42
 *      compiler.arguments.TestStressOptions
 * @run main/othervm -XX:+UnlockDiagnosticVMOptions -XX:+StressLCM
 *      compiler.arguments.TestStressOptions
 * @run main/othervm -XX:+UnlockDiagnosticVMOptions -XX:+StressLCM -XX:StressSeed=42
 *      compiler.arguments.TestStressOptions
 * @run main/othervm -XX:+UnlockDiagnosticVMOptions -XX:+StressGCM
 *      compiler.arguments.TestStressOptions
 * @run main/othervm -XX:+UnlockDiagnosticVMOptions -XX:+StressGCM -XX:StressSeed=42
 *      compiler.arguments.TestStressOptions
 * @run main/othervm -XX:+UnlockDiagnosticVMOptions -XX:+StressMacroExpansion
 *      compiler.arguments.TestStressOptions
 * @run main/othervm -XX:+UnlockDiagnosticVMOptions -XX:+StressMacroExpansion -XX:StressSeed=42
 *      compiler.arguments.TestStressOptions
 * @run main/othervm -XX:+UnlockDiagnosticVMOptions -XX:+StressIncrementalInlining
 *      compiler.arguments.TestStressOptions
 * @run main/othervm -XX:+UnlockDiagnosticVMOptions -XX:+StressIncrementalInlining -XX:StressSeed=42
 *      compiler.arguments.TestStressOptions
 * @run main/othervm -XX:+UnlockDiagnosticVMOptions -XX:+StressUnstableIfTraps
 *      compiler.arguments.TestStressOptions
 * @run main/othervm -XX:+UnlockDiagnosticVMOptions -XX:+StressUnstableIfTraps -XX:StressSeed=42
 *      compiler.arguments.TestStressOptions
 * @run main/othervm -XX:+UnlockDiagnosticVMOptions -XX:+StressMacroElimination
 *      compiler.arguments.TestStressOptions
 * @run main/othervm -XX:+UnlockDiagnosticVMOptions -XX:+StressMacroElimination -XX:StressSeed=42
 *      compiler.arguments.TestStressOptions
 */

package compiler.arguments;

public class TestStressOptions {

    static public void main(String[] args) {
        System.out.println("Passed");
    }
}
