package symmetricCipher

import "testing"

func TestSCEncryptString(t *testing.T) {
	type args struct {
		originalText string
		key          string
		scType       string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "测试des加密",
			args: args{
				originalText: "hello world",
				key:          "12345678", //占8字节
				scType:       "des",
			},
			want:    "CyqS6B+0nOGkMmaqyup7gQ==",
			wantErr: false,
		},
		{
			name: "测试3des加密",
			args: args{
				originalText: "hello world",
				key:          "abcdefgh0123456712345678", //占24字节
				scType:       "3des",
			},
			want:    "IfT5orD+hyrDE2788kpjwA==",
			wantErr: false,
		},
		{
			name: "测试aes加密",
			args: args{
				originalText: "hello world",
				key:          "abcdefgh0123456712345678", //占24字节
				scType:       "aes",
			},
			want:    "E351k97nQ2m26VYgmCHi+A==",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SCEncryptString(tt.args.originalText, tt.args.key, tt.args.scType)
			if (err != nil) != tt.wantErr {
				t.Errorf("SCEncryptString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SCEncryptString() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSCDecryptString(t *testing.T) {
	type args struct {
		chipherText string
		key         string
		scType      string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "测试des解密",
			args: args{
				chipherText: "CyqS6B+0nOGkMmaqyup7gQ==",
				key:         "12345678", //占8字节
				scType:      "des",
			},
			want:    "hello world",
			wantErr: false,
		},
		{
			name: "测试3des解密",
			args: args{
				chipherText: "IfT5orD+hyrDE2788kpjwA==",
				key:         "abcdefgh0123456712345678", //占24字节
				scType:      "3des",
			},
			want:    "hello world",
			wantErr: false,
		},
		{
			name: "测试aes解密",
			args: args{
				chipherText: "E351k97nQ2m26VYgmCHi+A==",
				key:         "abcdefgh0123456712345678", //占24字节
				scType:      "aes",
			},
			want:    "hello world",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SCDecryptString(tt.args.chipherText, tt.args.key, tt.args.scType)
			if (err != nil) != tt.wantErr {
				t.Errorf("SCDecryptString() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SCDecryptString() got = %v, want %v", got, tt.want)
			}
		})
	}
}
