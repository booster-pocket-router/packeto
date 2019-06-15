// Copyright © 2019 booster authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

package cmd

import (
	"fmt"
	"flag"
	"os"
	"strings"
	"io"

	"github.com/spf13/cobra"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/dumpcommand"
)

var iface string

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "packeto",
	Short: "A brief description of your application",
	Run: func(cmd *cobra.Command, args []string) {
		handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error%v\n", err)
			os.Exit(1)
		}

		// BPF filter
		info, err := os.Stdin.Stat()
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
		if info.Size() > 0 {
			var builder strings.Builder
			_, err := io.Copy(&builder, os.Stdin)
			if err != nil {
				fmt.Fprintf(os.Stderr, "unable to read from stdin: %v\n", err)
				os.Exit(1)
			}

			filter := builder.String()
			fmt.Fprintf(os.Stderr, "using BPF filter %q\n", filter)
			if err = handle.SetBPFFilter(filter); err != nil {
				fmt.Fprintf(os.Stderr, "unable to read from stdin: %v\n", err)
				os.Exit(1)
			}
		}

		flag.Parse() // required by Run function
		dumpcommand.Run(handle)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().StringVarP(&iface, "interface", "i", "en0", "target interface name")
}
