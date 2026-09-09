# typed: false
# frozen_string_literal: true

# Homebrew formula for the Hirsch SecureFIDO device-configuration CLI.
#
# Regenerate the `resource` blocks after a dependency bump with:
#     ./scripts/brew_release.sh <version>
#
# The top-level `sha256` is a placeholder until the sdist is published to
# PyPI; `scripts/brew_release.sh` fills in the real digest. See HOMEBREW.md.
class HirschSecurefido < Formula
  include Language::Python::Virtualenv

  desc "Device configuration CLI for Hirsch SecureKey FIDO2 authenticators"
  homepage "https://github.com/hirschsecure/hirsch-securefido"
  url "https://files.pythonhosted.org/packages/source/h/hirsch-securefido/hirsch_securefido-1.0.0.tar.gz"
  sha256 "REPLACE_WITH_SDIST_SHA256"
  license "BSD-3-Clause"

  depends_on "python@3.12"

  # cryptography ships prebuilt wheels, but Homebrew builds from source, so the
  # Rust toolchain is required to compile its extension modules.
  depends_on "rust" => :build

  resource "cffi" do
    url "https://files.pythonhosted.org/packages/9e/ef/008a1939e372c06329a3fce4279c02f328488f3526744906eeec3da7ad5f/cffi-2.1.1.tar.gz"
    sha256 "dd31f52ea1086513bb9df30f8fcee9b8918323ae067a3d5b78bc826a000712be"
  end

  resource "pycparser" do
    url "https://files.pythonhosted.org/packages/1b/7d/92392ff7815c21062bea51aa7b87d45576f649f16458d78b7cf94b9ab2e6/pycparser-3.0.tar.gz"
    sha256 "600f49d217304a5902ac3c37e1281c9fe94e4d0489de643a9504c5cdfdfc6b29"
  end

  resource "cryptography" do
    url "https://files.pythonhosted.org/packages/bb/ad/5d6702db60b1e40b41ef513b6967ff5848f307d50f8449baf1634f5908f1/cryptography-50.0.1.tar.gz"
    sha256 "5dd9bda1c12b4162f6ff568eeb5e0ff956c28d14406e875cfe8a63a2d414ff20"
  end

  resource "fido2" do
    url "https://files.pythonhosted.org/packages/ba/ea/6f08c354b7aeb8019249d46a86c2153f8218499cced4d21bf16b6d49fc16/fido2-2.2.1.tar.gz"
    sha256 "85787428a94c3f8eaf72f0ff30afba983b559a1b1b795c93318c81b4ad4062c4"
  end

  def install
    virtualenv_install_with_resources
  end

  def caveats
    <<~EOS
      hirsch-securefido talks to FIDO2 authenticators over USB HID.
      No sudo is required on macOS: HID access is granted to the console user.

      Verify your setup with:
        hirsch-securefido list
        hirsch-securefido info

      NFC / smart-card readers need the optional pyscard extra:
        $(brew --prefix)/opt/hirsch-securefido/libexec/bin/pip install pyscard
    EOS
  end

  test do
    # Version reporting must work with no hardware attached.
    assert_match version.to_s, shell_output("#{bin}/hirsch-securefido --version")

    # Help must advertise exactly the four device-configuration commands.
    help = shell_output("#{bin}/hirsch-securefido --help")
    ["info", "set-pin", "change-pin", "reset"].each do |cmd|
      assert_match cmd, help
    end

    # With no authenticator present the tool must exit 2 (EXIT_NO_DEVICE)
    # rather than crash with a traceback.
    output = shell_output("#{bin}/hirsch-securefido info 2>&1", 2)
    assert_match "No Hirsch FIDO2 token found", output

    # The library must import cleanly inside the virtualenv.
    system libexec/"bin/python", "-c", "import hirsch_securefido"
  end
end
