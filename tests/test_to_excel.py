import os
import shutil

import requests

from mitreattack.attackToExcel import attackToExcel


class TestAttackToExcel:
    def test_enterprise_latest(self):
        """Test most recent enterprise to excel spreadsheet functionality"""
        if os.path.isdir("test_attacktoexcel_exports_enterprise"):
            shutil.rmtree("test_attacktoexcel_exports_enterprise")

        try:
            attackToExcel.export(domain="enterprise-attack", output_dir="test_attacktoexcel_exports_enterprise")
            shutil.rmtree("test_attacktoexcel_exports_enterprise")
        except requests.exceptions.SSLError:
            print("UNABLE TO RUN TEST DUE TO CERT ISSUE.")

    def test_mobile_latest(self):
        """Test most recent mobile to excel spreadsheet functionality"""
        if os.path.isdir("test_attacktoexcel_exports_mobile"):
            shutil.rmtree("test_attacktoexcel_exports_mobile")
        try:
            attackToExcel.export(domain="mobile-attack", output_dir="test_attacktoexcel_exports_mobile")
            shutil.rmtree("test_attacktoexcel_exports_mobile")
        except requests.exceptions.SSLError:
            print("UNABLE TO RUN TEST DUE TO CERT ISSUE.")

    def test_ics_latest(self):
        """Test most recent ics to excel spreadsheet functionality"""
        if os.path.isdir("test_attacktoexcel_exports_ics"):
            shutil.rmtree("test_attacktoexcel_exports_ics")

        try:
            attackToExcel.export(domain="ics-attack", output_dir="test_attacktoexcel_exports_ics")
            shutil.rmtree("test_attacktoexcel_exports_ics")
        except requests.exceptions.SSLError:
            print("UNABLE TO RUN TEST DUE TO CERT ISSUE.")

    def test_enterprise_legacy(self):
        """Test enterprise v9.0 to excel spreadsheet functionality"""
        if os.path.isdir("test_attacktoexcel_exports_enterprise"):
            shutil.rmtree("test_attacktoexcel_exports_enterprise")

        try:
            attackToExcel.export(
                domain="enterprise-attack", version="9.0", output_dir="test_attacktoexcel_exports_enterprise"
            )
            shutil.rmtree("test_attacktoexcel_exports_enterprise")
        except requests.exceptions.SSLError:
            print("UNABLE TO RUN TEST DUE TO CERT ISSUE.")
